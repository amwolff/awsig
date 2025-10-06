package awsig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

func TestNestedError(t *testing.T) {
	outer := errors.New("outer")
	inner := errors.New("inner")

	nested := nestError(outer, "oops: %w", inner)

	t.Run("Error", func(t *testing.T) {
		assert.Equal(t, "outer: oops: inner", nested.Error())
	})
	t.Run("Unwrap", func(t *testing.T) {
		assert.Equal(t, inner, errors.Unwrap(errors.Unwrap(nested)))
	})
	t.Run("Is", func(t *testing.T) {
		assert.That(t, errors.Is(nested, outer))
		assert.That(t, errors.Is(nested, inner))
	})
}

func TestTimeOutOfBounds(t *testing.T) {
	t.Run("within bounds", func(t *testing.T) {
		now := dummyNow(1970, 1, 1, 2, 0, 0)
		b1 := time.Date(1970, 1, 1, 1, 0, 0, 0, time.UTC)
		b2 := time.Date(1970, 1, 1, 3, 0, 0, 0, time.UTC)
		assert.False(t, timeOutOfBounds(now, b1, b2))
	})
	t.Run("before bounds", func(t *testing.T) {
		now := dummyNow(1970, 1, 2, 3, 0, 0)
		b1 := time.Date(1970, 1, 2, 3, 1, 0, 0, time.UTC)
		b2 := time.Date(1970, 1, 2, 3, 3, 0, 0, time.UTC)
		assert.True(t, timeOutOfBounds(now, b1, b2))
	})
	t.Run("after bounds", func(t *testing.T) {
		now := dummyNow(1970, 1, 2, 4, 4, 4)
		b1 := time.Date(1970, 1, 2, 3, 4, 1, 0, time.UTC)
		b2 := time.Date(1970, 1, 2, 3, 4, 3, 0, time.UTC)
		assert.True(t, timeOutOfBounds(now, b1, b2))
	})
	t.Run("swapped bounds", func(t *testing.T) {
		now := dummyNow(1970, 1, 1, 2, 0, 0)
		b1 := time.Date(1970, 1, 1, 3, 0, 0, 0, time.UTC)
		b2 := time.Date(1970, 1, 1, 1, 0, 0, 0, time.UTC)
		assert.False(t, timeOutOfBounds(now, b1, b2))
	})
}

func TestTimeSkewExceeded(t *testing.T) {
	t.Run("within skew", func(t *testing.T) {
		now := dummyNow(1970, 1, 1, 2, 0, 0)
		d := time.Date(1970, 1, 1, 2, 4, 0, 0, time.UTC)
		assert.False(t, timeSkewExceeded(now, d, 5*time.Minute))
	})
	t.Run("exceeds skew", func(t *testing.T) {
		now := dummyNow(1970, 1, 1, 2, 0, 0)
		d := time.Date(1970, 1, 1, 2, 6, 0, 0, time.UTC)
		assert.True(t, timeSkewExceeded(now, d, 5*time.Minute))
	})
}

func TestURIEncode(t *testing.T) {
	const (
		testPath   = "photos/Jan/sample.jpg"
		unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	)
	assert.Equal(t, testPath, uriEncode(testPath, true))
	assert.Equal(t, unreserved+"with%20spaces", uriEncode(unreserved+"with spaces", false))
}

func TestHashBuilder(t *testing.T) {
	const (
		hashZero = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		hashTest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	)

	b := newHashBuilder(sha256.New)
	b.Write(nil)
	b.WriteString("")
	assert.Equal(t, hashZero, hex.EncodeToString(b.Sum()))
	b.Write([]byte("test"))
	assert.Equal(t, hashTest, hex.EncodeToString(b.Sum()))
	b.WriteByte('!')
	assert.Equal(t, "1882b91b7f49d479cf1ec2f1ecee30d0e5392e963a2109015b7149bf712ad1b6", hex.EncodeToString(b.Sum()))
	b.WriteString("!!")
	assert.Equal(t, "28f0f0df65f6e12393536e8b76b4a227e2e84c323cc4d3fdd5e56966f29019ad", hex.EncodeToString(b.Sum()))
}

func TestLimitedReader(t *testing.T) {
	expected := make([]byte, 30)
	_, err := io.ReadFull(rand.Reader, expected)
	assert.NoError(t, err)

	r := limitReader(bytes.NewReader(expected), 10)

	b := make([]byte, 9)
	n, err := io.ReadFull(r, b)
	assert.Equal(t, 9, n)
	assert.NoError(t, err)
	assert.Equal(t, expected[:9], b)

	b = make([]byte, 11)
	n, err = io.ReadFull(r, b)
	assert.Equal(t, 1, n)
	assert.That(t, errors.Is(err, io.EOF))
	assert.That(t, errors.Is(err, errLimitReached))
	assert.Equal(t, expected[9:10], b[:1])
	assert.Equal(t, make([]byte, 10), b[1:])

	r.toggle()

	b = make([]byte, 10)
	n, err = io.ReadFull(r, b)
	assert.Equal(t, 10, n)
	assert.NoError(t, err)
	assert.Equal(t, expected[10:20], b)

	r.toggle()

	b, err = io.ReadAll(r)
	assert.Equal(t, 0, len(b))
	assert.That(t, errors.Is(err, io.EOF))
	assert.That(t, errors.Is(err, errLimitReached))

	r.toggle()

	b, err = io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, expected[20:], b)
}

func TestParseMultipartFormUntilFile(t *testing.T) {
	newMultipart := func(formFields int, filename string, filesize int64) ([]byte, map[string][]string, *bytes.Buffer, string) {
		fields, body := make(map[string][]string), bytes.NewBuffer(nil)

		mw := multipart.NewWriter(body)
		defer func() { assert.NoError(t, mw.Close()) }()

		for i := range formFields {
			a := strconv.Itoa(i)
			name, value := "field_"+a, "value_"+a
			fields[name] = append(fields[name], value)
			assert.NoError(t, mw.WriteField(name, value))
		}

		if filename == "" {
			return nil, fields, body, mw.Boundary()
		}

		file := bytes.NewBuffer(nil)

		part, err := mw.CreateFormFile("file", filename)
		assert.NoError(t, err)
		_, err = io.CopyN(part, io.TeeReader(rand.Reader, file), filesize)
		assert.NoError(t, err)

		return file.Bytes(), fields, body, mw.Boundary()
	}

	t.Run("no boundary", func(t *testing.T) {
		_, _, body, _ := newMultipart(10, "image.jpg", 10)

		_, _, err := parseMultipartFormUntilFile(body, "")
		assert.Error(t, err)
	})
	t.Run("no file", func(t *testing.T) {
		_, _, body, boundary := newMultipart(10, "", 0)

		_, _, err := parseMultipartFormUntilFile(body, boundary)
		assert.Error(t, err)
	})
	t.Run("form within the size limit", func(t *testing.T) {
		expectedFile, expectedForm, body, boundary := newMultipart(100, "image.jpg", 30000)

		file, actualForm, err := parseMultipartFormUntilFile(body, boundary)
		assert.NoError(t, err)
		defer func() { assert.NoError(t, file.Close()) }()

		assert.Equal(t, "image.jpg", actualForm.FileName())

		actualFile, err := io.ReadAll(file)
		assert.NoError(t, err)
		assert.Equal(t, expectedFile, actualFile)

		for name, values := range expectedForm {
			{
				actual, headers := actualForm.Get(name)
				assert.Equal(t, values[0], actual)
				assert.Equal(t, 1, len(headers))
			}
			{
				actual, headers := actualForm.Values(name)
				assert.Equal(t, values, actual)
				assert.Equal(t, 1, len(headers))
			}
		}
	})
	t.Run("form above limit", func(t *testing.T) {
		_, _, body, boundary := newMultipart(1000, "image.jpg", 1000)

		_, _, err := parseMultipartFormUntilFile(body, boundary)
		assert.Error(t, err)
		assert.That(t, errors.Is(err, errMessageTooLarge))
	})
	t.Run("form above limit with bogus boundary", func(t *testing.T) {
		_, _, body, _ := newMultipart(1000, "image.jpg", 1000)

		_, _, err := parseMultipartFormUntilFile(body, "bogus")
		assert.Error(t, err)
		assert.That(t, errors.Is(err, errMessageTooLarge))
	})
}

type verifier[T VerifiedRequest] interface {
	Verify(r *http.Request, virtualHostedBucket string) (T, error)
}

type simpleCredentialsProvider struct {
	accessKeyID     string
	secretAccessKey string
}

func (p simpleCredentialsProvider) Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error) {
	if accessKeyID != p.accessKeyID {
		return "", ErrInvalidAccessKeyID
	}
	return p.secretAccessKey, nil
}

func dummyNow(year int, month time.Month, day, hour, min, sec int) func() time.Time {
	return func() time.Time {
		return time.Date(year, month, day, hour, min, sec, 0, time.UTC)
	}
}
