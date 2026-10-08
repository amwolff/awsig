package awsig

import (
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStreamingMinimumChunkIs8KiB(t *testing.T) {
	for _, tc := range []struct {
		first int
		want  error
	}{
		{8191, ErrInvalidChunkSize},
		{8192, nil},
	} {
		t.Run(fmt.Sprint(tc.first), func(t *testing.T) {
			body := fmt.Sprintf("%x\r\n%s\r\n1\r\nb\r\n0\r\n\r\n", tc.first, strings.Repeat("a", tc.first))
			vr, err := newV4VerifiedRequest(strings.NewReader(body), v4VerifiedData[struct{}]{options: parsedXAmzContentSHA256{
				unsigned:             true,
				streaming:            true,
				decodedContentLength: int64(tc.first + 1),
			}})
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
			if tc.want != nil && !errors.Is(err, ErrEntityTooSmall) {
				t.Fatalf("got %v, want it to also match ErrEntityTooSmall", err)
			}
		})
	}
}

func TestV4UnsignedHeaders(t *testing.T) {
	v := NewV4(simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	for _, header := range []string{"x-amz-meta-foo", "Content-MD5"} {
		t.Run(header, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
			r.Header.Set("Range", "bytes=0-9")
			r.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			r.Header.Set("x-amz-date", "20130524T000000Z")
			if _, err := v.Verify(r); err != nil {
				t.Fatal(err)
			}
			r.Header.Set(header, "1B2M2Y8AsgTpgAmY7PhCfg==") // added after signing
			if _, err := v.Verify(r); !errors.Is(err, ErrUnsignedHeader) {
				t.Fatalf("got %v, want ErrUnsignedHeader", err)
			}
		})
	}
}

func TestV4PresignedMalformedAuthorization(t *testing.T) {
	v := NewV4(simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)
	for _, tc := range []struct{ name, credential, signedHeaders string }{
		{"credential", "garbage", "host"},
		{"credential date", "AKIAIOSFODNN7EXAMPLE%2F20130523%2Fus-east-1%2Fs3%2Faws4_request", "host"},
		{"signed headers order", "AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request", "host%3Bcontent-type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="+tc.credential+
				"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders="+tc.signedHeaders+"&X-Amz-Signature="+strings.Repeat("0", 64), nil)
			_, err := v.Verify(r)
			if !errors.Is(err, ErrAuthorizationQueryParametersError) {
				t.Fatalf("got %v, want ErrAuthorizationQueryParametersError", err)
			}
			if errors.Is(err, ErrAuthorizationHeaderMalformed) {
				t.Fatal("presigned request reported a header error")
			}
		})
	}
}
