package awsig

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

const (
	testDefaultRegion  = "us-east-1"
	testDefaultService = "s3"
)

type v4Verifier[T any] struct {
	v4 *V4[T]
}

func (v *v4Verifier[T]) Verify(r *http.Request, _ string) (*V4VerifiedRequest[T], error) {
	return v.v4.Verify(r)
}

func TestV4(t *testing.T) {
	newV4 := func(provider CredentialsProvider[exampleAuthData], now func() time.Time) verifier[*V4VerifiedRequest[exampleAuthData]] {
		v4 := NewV4(provider, V4Config{
			Region:  testDefaultRegion,
			Service: testDefaultService,
		})
		v4.now = now
		return &v4Verifier[exampleAuthData]{v4: v4}
	}
	testV4(t, newV4)
}

func testV4[T VerifiedRequest[exampleAuthData]](t *testing.T, newV4 func(CredentialsProvider[exampleAuthData], func() time.Time) verifier[T]) {
	const accessKeyID = "AKIAIOSFODNN7EXAMPLE"

	provider := simpleCredentialsProvider{
		accessKeyID:     accessKeyID,
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	now := dummyNow(2013, time.May, 24, 0, 0, 0)
	v4 := newV4(provider, now)

	t.Run("single chunk", func(t *testing.T) {
		t.Run("GET Object", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
			req.Header.Add("Range", "bytes=0-9")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			req.Header.Add("x-amz-date", "20130524T000000Z")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			r, err := vr.Reader()
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
		t.Run("PUT Object", func(t *testing.T) {
			const content = "Welcome to Amazon S3."

			req := httptest.NewRequest(http.MethodPut, "https://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader(content))
			req.Header.Add("Date", "Fri, 24 May 2013 00:00:00 GMT")
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-storage-class", "REDUCED_REDUNDANCY")
			req.Header.Add("x-amz-content-sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			r, err := vr.Reader()
			assert.NoError(t, err)

			b, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, content, string(b))
		})
		t.Run("GET Bucket Lifecycle", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?lifecycle", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			r, err := vr.Reader()
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
		t.Run("Get Bucket (List Objects)", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7")
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			r, err := vr.Reader()
			assert.NoError(t, err)

			p := make([]byte, 32*1024)
			n, err := r.Read(p)
			assert.That(t, n == 0)
			assert.That(t, errors.Is(err, io.EOF))
		})
	})
	t.Run("multiple chunks", func(t *testing.T) {
		t.Run("PUT Object", func(t *testing.T) {
			body := bytes.NewBuffer(nil)
			body.WriteString("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n")
			for range 65536 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n")
			for range 1024 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n")

			req := httptest.NewRequest(http.MethodPut, "https://s3.amazonaws.com/examplebucket/chunkObject.txt", body)
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-storage-class", "REDUCED_REDUNDANCY")
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
			req.Header.Add("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
			req.Header.Add("Content-Encoding", "aws-chunked")
			req.Header.Add("x-amz-decoded-content-length", "66560")
			req.Header.Add("Content-Length", "66824")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			r, err := vr.Reader()
			assert.NoError(t, err)

			b, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, bytes.Repeat([]byte{'a'}, 65*1024), b)
		})
	})
	t.Run("trailing headers", func(t *testing.T) {
		t.Run("signed", func(t *testing.T) {
			body := bytes.NewBuffer(nil)
			body.WriteString("10000;chunk-signature=b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2\r\n")
			for range 65536 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("400;chunk-signature=1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7\r\n")
			for range 1024 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("0;chunk-signature=2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992\r\n")
			body.WriteString("x-amz-checksum-crc32c:sOO8/Q==\r\n")
			body.WriteString("x-amz-trailer-signature:d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435\r\n")

			req := httptest.NewRequest(http.MethodPut, "https://s3.amazonaws.com/examplebucket/chunkObject.txt", body)
			req.Header.Add("x-amz-date", "20130524T000000Z")
			req.Header.Add("x-amz-storage-class", "REDUCED_REDUNDANCY")
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class;x-amz-trailer,Signature=106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e")
			req.Header.Add("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
			req.Header.Add("Content-Encoding", "aws-chunked")
			req.Header.Add("x-amz-decoded-content-length", "66560")
			req.Header.Add("x-amz-trailer", "x-amz-checksum-crc32c")
			req.Header.Add("Content-Length", "66824")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			cr, err := NewTrailingChecksumRequest(AlgorithmCRC32C)
			assert.NoError(t, err)

			r, err := vr.Reader(cr)
			assert.NoError(t, err)

			b, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, bytes.Repeat([]byte{'a'}, 65*1024), b)

			checksums, err := r.Checksums()
			assert.NoError(t, err)
			assert.Equal(t, map[ChecksumAlgorithm][]byte{
				AlgorithmCRC32C: {0xb0, 0xe3, 0xbc, 0xfd},
				AlgorithmMD5:    {0xda, 0x0d, 0x2e, 0x17, 0xcd, 0x5a, 0x8f, 0x14, 0x63, 0x3c, 0x6b, 0x4a, 0xeb, 0xad, 0x7e, 0x02},
			}, checksums)
		})
		t.Run("unsigned", func(t *testing.T) {
			body := bytes.NewBuffer(nil)
			body.WriteString("2000\r\n")
			for range 8192 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("2000\r\n")
			for range 8192 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("400\r\n")
			for range 1024 {
				body.WriteByte('a')
			}
			body.WriteString("\r\n")
			body.WriteString("0\r\n")
			body.WriteString("x-amz-checksum-crc32:s3SFCQ==\n\r\n\r\n")

			req := httptest.NewRequest(http.MethodPut, "https://amzn-s3-demo-bucket.s3.amazonaws.com/Key+", body)
			req.Header.Add("Content-Encoding", "aws-chunked")
			req.Header.Add("x-amz-decoded-content-length", "17408")
			req.Header.Add("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
			req.Header.Add("x-amz-trailer", "x-amz-checksum-crc32")
			req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer,Signature=8fdf2b7a7005b82789d2a9cec832705457298e8a6a908f8c85f17e44c707aa64")
			req.Header.Add("Content-Length", strconv.Itoa(body.Len()))
			req.Header.Add("x-amz-date", "20130524T000000Z")

			vr, err := v4.Verify(req, "")
			assert.NoError(t, err)
			assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

			cr, err := NewTrailingChecksumRequest(AlgorithmCRC32)
			assert.NoError(t, err)

			r, err := vr.Reader(cr)
			assert.NoError(t, err)

			b, err := io.ReadAll(r)
			assert.NoError(t, err)
			assert.Equal(t, bytes.Repeat([]byte{'a'}, 17*1024), b)

			checksums, err := r.Checksums()
			assert.NoError(t, err)
			assert.Equal(t, map[ChecksumAlgorithm][]byte{
				AlgorithmCRC32: {0xb3, 0x74, 0x85, 0x09},
				AlgorithmMD5:   {0xdd, 0x1b, 0x90, 0x4c, 0x0c, 0x06, 0xf8, 0x01, 0x56, 0xc1, 0x38, 0x10, 0xa0, 0x4d, 0xbb, 0x94},
			}, checksums)
		})
	})
	t.Run("presigned", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", nil)

		vr, err := v4.Verify(req, "")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

		r, err := vr.Reader()
		assert.NoError(t, err)

		p := make([]byte, 32*1024)
		n, err := r.Read(p)
		assert.That(t, n == 0)
		assert.That(t, errors.Is(err, io.EOF))
	})
	t.Run("presigned (POST)", func(t *testing.T) {
		file := []byte("Hello World!")
		body := bytes.NewBuffer(nil)

		mw := multipart.NewWriter(body)

		assert.NoError(t, mw.WriteField("key", "user/user1/${filename}"))
		assert.NoError(t, mw.WriteField("acl", "public-read"))
		assert.NoError(t, mw.WriteField("success_action_redirect", "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"))
		assert.NoError(t, mw.WriteField("Content-Type", "image/jpeg"))
		assert.NoError(t, mw.WriteField("x-amz-meta-uuid", "14365123651274"))
		assert.NoError(t, mw.WriteField("x-amz-server-side-encryption", "AES256"))
		assert.NoError(t, mw.WriteField("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"))
		assert.NoError(t, mw.WriteField("X-Amz-Algorithm", "AWS4-HMAC-SHA256"))
		assert.NoError(t, mw.WriteField("X-Amz-Date", "20151229T000000Z"))
		assert.NoError(t, mw.WriteField("x-amz-meta-tag", ""))
		assert.NoError(t, mw.WriteField("Policy", "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"))
		assert.NoError(t, mw.WriteField("X-Amz-Signature", "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"))

		part, err := mw.CreateFormFile("file", "hello.txt")
		assert.NoError(t, err)
		_, err = io.Copy(part, bytes.NewReader(file))
		assert.NoError(t, err)

		assert.NoError(t, mw.Close())

		req := httptest.NewRequest(http.MethodPost, "http://sigv4examplebucket.s3.amazonaws.com/", body)
		req.Header.Add("Content-Type", mw.FormDataContentType())

		v4 := newV4(provider, dummyNow(2015, time.December, 29, 0, 0, 0))

		vr, err := v4.Verify(req, "")
		assert.NoError(t, err)
		assert.Equal(t, accessKeyID, vr.AuthData().accessKeyID)

		r, err := vr.Reader()
		assert.NoError(t, err)

		b, err := io.ReadAll(r)
		assert.NoError(t, err)
		assert.Equal(t, file, b)
	})
	t.Run("presigned (POST, not yet valid)", func(t *testing.T) {
		file := []byte("Hello World!")
		body := bytes.NewBuffer(nil)

		mw := multipart.NewWriter(body)

		assert.NoError(t, mw.WriteField("key", "user/user1/${filename}"))
		assert.NoError(t, mw.WriteField("acl", "public-read"))
		assert.NoError(t, mw.WriteField("success_action_redirect", "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html"))
		assert.NoError(t, mw.WriteField("Content-Type", "image/jpeg"))
		assert.NoError(t, mw.WriteField("x-amz-meta-uuid", "14365123651274"))
		assert.NoError(t, mw.WriteField("x-amz-server-side-encryption", "AES256"))
		assert.NoError(t, mw.WriteField("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"))
		assert.NoError(t, mw.WriteField("X-Amz-Algorithm", "AWS4-HMAC-SHA256"))
		assert.NoError(t, mw.WriteField("X-Amz-Date", "20151229T000000Z"))
		assert.NoError(t, mw.WriteField("x-amz-meta-tag", ""))
		assert.NoError(t, mw.WriteField("Policy", "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"))
		assert.NoError(t, mw.WriteField("X-Amz-Signature", "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"))

		part, err := mw.CreateFormFile("file", "hello.txt")
		assert.NoError(t, err)
		_, err = io.Copy(part, bytes.NewReader(file))
		assert.NoError(t, err)

		assert.NoError(t, mw.Close())

		req := httptest.NewRequest(http.MethodPost, "http://sigv4examplebucket.s3.amazonaws.com/", body)
		req.Header.Add("Content-Type", mw.FormDataContentType())

		v4 := newV4(provider, dummyNow(2015, time.December, 28, 0, 0, 0))

		_, err = v4.Verify(req, "")
		assert.That(t, errors.Is(err, ErrAccessDenied))
	})

	t.Run("signed header with empty value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/", nil)
		req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-type;host;x-amz-date,Signature=0ed109d305d381a42dd12b1b04ccbb95b690b0d8571d07e6c55765a8044f1d15")
		req.Header.Add("Content-Type", "")
		req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		req.Header.Add("x-amz-date", "20130524T000000Z")

		_, err := v4.Verify(req, "")
		assert.NoError(t, err)
	})

	t.Run("skip region verification", func(t *testing.T) {
		v4 := NewV4(provider, V4Config{
			Service:                testDefaultService,
			SkipRegionVerification: true,
		})
		v4.now = now

		req := httptest.NewRequest(http.MethodHead, "https://examplebucket.s3.amazonaws.com/", nil)
		req.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/eu-west-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=20ef61ac2576e9b79369952b7b4eaeb685c28b6b63737912ffe706ccf423f90c")
		req.Header.Add("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		req.Header.Add("x-amz-date", "20130524T000000Z")

		_, err := v4.Verify(req)
		assert.NoError(t, err)
	})
}
