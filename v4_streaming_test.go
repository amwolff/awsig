package awsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signedStreamingReader(t *testing.T, suffix string) Reader {
	t.Helper()
	provider := simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	v := NewV4(provider, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	body := bytes.NewBufferString("10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n")
	body.Write(bytes.Repeat([]byte{'a'}, 65536))
	body.WriteString("\r\n400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n")
	body.Write(bytes.Repeat([]byte{'a'}, 1024))
	body.WriteString("\r\n0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n" + suffix)
	r := httptest.NewRequest("PUT", "https://s3.amazonaws.com/examplebucket/chunkObject.txt", body)
	r.Header.Set("x-amz-date", "20130524T000000Z")
	r.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
	r.Header.Set("x-amz-content-sha256", streamingAWS4HMACSHA256Payload)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("x-amz-decoded-content-length", "66560")
	r.Header.Set("Content-Length", "66824")
	vr, err := v.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := vr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

func TestStreamingTerminator(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		want         error
	}{
		{"valid", "\r\n", nil},
		{"missing", "", io.ErrUnexpectedEOF},
		{"truncated", "\r", io.ErrUnexpectedEOF},
		{"invalid", "xx", ErrInvalidRequest},
		{"extra data", "\r\nx", ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := signedStreamingReader(t, tc.suffix)
			b, err := io.ReadAll(rd)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want == nil {
				if !bytes.Equal(b, bytes.Repeat([]byte{'a'}, 66560)) {
					t.Fatal("incorrect payload")
				}
				if _, err = rd.Read(make([]byte, 128)); err != io.EOF {
					t.Fatalf("read after EOF: %v", err)
				}
				if _, err = rd.Checksums(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestStreamingReadBufferSizes(t *testing.T) {
	for _, size := range []int{1, 2, 16, 80, 128, 512} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			rd := signedStreamingReader(t, "\r\n")
			if n, err := rd.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty read: %d, %v", n, err)
			}
			var payload bytes.Buffer
			buf := make([]byte, size)
			for {
				n, err := rd.Read(buf)
				payload.Write(buf[:n])
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(payload.Bytes(), bytes.Repeat([]byte{'a'}, 66560)) {
				t.Fatal("incorrect payload")
			}
			if _, err := rd.Checksums(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStreamingRejectsSignedLengths(t *testing.T) {
	for _, chunk := range []string{"-1", "+1"} {
		t.Run(chunk, func(t *testing.T) {
			r := &v4Reader{
				r:                    strings.NewReader(chunk + "\r\nxx"),
				unsigned:             true,
				multipleChunks:       true,
				trailingHeader:       true,
				decodedContentLength: -5,
			}
			r.ir = newIntegrityReader(r.r, nil)
			if _, err := io.ReadAll(r); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v, want %v", err, ErrInvalidRequest)
			}
		})
	}

	v := NewV4[struct{}](nil, V4Config{})
	for _, value := range []string{"-1", "+1"} {
		h := http.Header{}
		h.Set(headerXAmzDecodedContentLength, value)
		if _, err := v.decodedContentLength(h); !errors.Is(err, ErrInvalidXAmzDecodedContentLength) {
			t.Fatalf("%s: got %v, want %v", value, err, ErrInvalidXAmzDecodedContentLength)
		}
	}
}

func TestStreamingNineDigitChunkLength(t *testing.T) {
	for _, tc := range []struct {
		chunk string
		want  error
	}{
		{"140000000", io.ErrUnexpectedEOF}, // 5 GiB is accepted; body is missing
		{"140000001", ErrEntityTooLarge},
		{"1400000000", ErrInvalidRequest},
	} {
		t.Run(tc.chunk, func(t *testing.T) {
			r := &v4Reader{
				r:                    strings.NewReader(tc.chunk + "\r\n"),
				unsigned:             true,
				multipleChunks:       true,
				trailingHeader:       true,
				decodedContentLength: 1 << 40,
			}
			r.ir = newIntegrityReader(r.r, nil)
			if _, err := r.Read(make([]byte, 16)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStreamingErrorsAreTerminal(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		length     int64
		signed     bool
		want       error
	}{
		{"small chunk", "1\r\nZ\r\n", 100, false, ErrEntityTooSmall},
		{"large chunk", "140000001\r\nZ", 1, false, ErrEntityTooLarge},
		{"decoded length exceeded", "2\r\nZZ\r\n", 1, false, ErrInvalidRequest},
		{"bad signature", "1;chunk-signature=" + strings.Repeat("0", 64) + "\r\nZ\r\n", 1, true, ErrSignatureDoesNotMatch},
		{"truncated chunk", "2\r\nZ", 2, false, io.ErrUnexpectedEOF},
		{"malformed length", "-1\r\nZ", 1, false, ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := bytes.NewBufferString(tc.body)
			vr, err := newV4VerifiedRequest(source, v4VerifiedData[struct{}]{options: parsedXAmzContentSHA256{unsigned: !tc.signed, streaming: true, decodedContentLength: tc.length}})
			if err != nil {
				t.Fatal(err)
			}
			rd, err := vr.Reader()
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(rd)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			remaining := source.Len()
			for range 3 {
				n, next := rd.Read(make([]byte, 128))
				if n != 0 || next != err {
					t.Fatalf("after %v got %d bytes, %v", err, n, next)
				}
				if source.Len() != remaining {
					t.Fatal("read consumed data after failure")
				}
			}
			if tc.signed && vr.wrapped.decodedContentLength != 0 {
				t.Fatal("failed signature skipped decoded length accounting")
			}
		})
	}
	t.Run("checksum", func(t *testing.T) {
		rd := signedStreamingReader(t, "\r\n").(*v4Reader)
		rd.integrity[AlgorithmMD5] = make([]byte, 16)
		_, err := io.ReadAll(rd)
		if !errors.Is(err, ErrBadDigest) {
			t.Fatal(err)
		}
		if n, next := rd.Read(make([]byte, 128)); n != 0 || next != err {
			t.Fatalf("got %d, %v after %v", n, next, err)
		}
	})
}
