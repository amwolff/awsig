package awsig

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// unsignedTrailerRequest returns a request whose signature is never checked:
// every case fails or is inspected before signature verification.
func unsignedTrailerRequest(contentSHA256 string, trailer ...string) *http.Request {
	r := httptest.NewRequest("PUT", "https://s3.amazonaws.com/bucket/key", strings.NewReader(""))
	r.Header.Set("x-amz-date", "20130524T000000Z")
	r.Header.Set("x-amz-content-sha256", contentSHA256)
	r.Header.Set("x-amz-decoded-content-length", "5")
	signed := "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length"
	for _, v := range trailer {
		r.Header.Add("x-amz-trailer", v)
	}
	if len(trailer) > 0 {
		signed += ";x-amz-trailer"
	}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders="+signed+",Signature="+strings.Repeat("0", 64))
	return r
}

func TestV4TrailerHeaderValidation(t *testing.T) {
	provider := simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	v := NewV4(provider, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = dummyNow(2013, time.May, 24, 0, 0, 0)

	for _, tc := range []struct {
		name    string
		payload string
		trailer []string
		want    error
	}{
		{"missing", streamingUnsignedPayloadTrailer, nil, ErrMalformedTrailer},
		{"unsupported", streamingUnsignedPayloadTrailer, []string{"x-amz-checksum-foo"}, ErrInvalidRequest},
		{"not a checksum", streamingUnsignedPayloadTrailer, []string{"x-amz-meta-foo"}, ErrInvalidRequest},
		{"repeated", streamingUnsignedPayloadTrailer, []string{"x-amz-checksum-crc32", "x-amz-checksum-crc32"}, ErrInvalidRequest},
		{"without trailer mode", unsignedPayload, []string{"x-amz-checksum-crc32"}, ErrInvalidRequest},
		{"valid", streamingUnsignedPayloadTrailer, []string{" X-Amz-Checksum-CRC32 "}, ErrSignatureDoesNotMatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(unsignedTrailerRequest(tc.payload, tc.trailer...))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestV4PresignedRejectsUnexpectedTrailer(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	v := NewV4(simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"}, V4Config{Region: "us-east-1", Service: "s3"})
	v.now = func() time.Time { return now }
	for _, trailer := range []string{"", "x-amz-checksum-crc32", "x-amz-checksum-foo"} {
		t.Run(trailer, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://example.com/bucket/key", nil)
			sc := scope{date: "20260923", region: "us-east-1", service: "s3"}
			q := url.Values{}
			q.Set(queryXAmzAlgorithm, "AWS4-HMAC-SHA256")
			q.Set(queryXAmzCredential, "key/"+sc.String())
			q.Set(queryXAmzDate, now.Format(timeFormatISO8601))
			q.Set(queryXAmzExpires, "3600")
			q.Set(queryXAmzSignedHeaders, "host")
			sig := calculateSignatureV4(signatureV4Data{dateTime: now.Format(timeFormatISO8601), scope: sc, digest: v.canonicalRequestHash(r, q, []string{"host"}, unsignedPayload)}, "secret")
			q.Set(queryXAmzSignature, sig.String())
			r.URL.RawQuery = q.Encode()
			if trailer != "" {
				r.Header.Set(headerXAmzTrailer, trailer)
				q := r.URL.Query()
				q.Del(queryXAmzSignature)
				q.Set(queryXAmzSignedHeaders, "host;x-amz-trailer")
				sig := calculateSignatureV4(signatureV4Data{
					dateTime: now.Format(timeFormatISO8601),
					scope:    scope{date: "20260923", region: "us-east-1", service: "s3"},
					digest:   v.canonicalRequestHash(r, q, []string{"host", headerXAmzTrailer}, unsignedPayload),
				}, "secret")
				q.Set(queryXAmzSignature, sig.String())
				r.URL.RawQuery = q.Encode()
			}
			var want error
			if trailer != "" {
				want = ErrInvalidRequest
			}
			if _, err := v.Verify(r); !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

func unsignedTrailerVerifiedRequest(t *testing.T, body string, trailerAlgo ChecksumAlgorithm) *V4VerifiedRequest[struct{}] {
	t.Helper()
	vr, err := newV4VerifiedRequest(strings.NewReader(body), v4VerifiedData[struct{}]{options: parsedXAmzContentSHA256{
		unsigned:             true,
		streaming:            true,
		trailer:              true,
		trailerAlgo:          trailerAlgo,
		decodedContentLength: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return vr
}

func TestV4TrailerDefaultsToHeaderAlgorithm(t *testing.T) {
	vr := unsignedTrailerVerifiedRequest(t, "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:NhCmhg==\r\n\r\n", AlgorithmCRC32)
	rd, err := vr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(rd); err != nil || string(b) != "hello" {
		t.Fatalf("got %q, %v", b, err)
	}
	sums, err := rd.Checksums()
	if err != nil || len(sums[AlgorithmCRC32]) != 4 {
		t.Fatalf("got %v, %v", sums, err)
	}
}

func TestV4TrailerMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, trailer string
		want          error
	}{
		{"other algorithm", "x-amz-checksum-sha1:qvTGHdzF6KLavt4PO0gs2a6pQ00=\r\n\r\n", ErrMalformedTrailer},
		{"other header", "x-amz-meta-foooooo:NhCmhg==\r\n\r\n", ErrMalformedTrailer},
		{"unterminated", "x-amz-checksum-crc32:NhCmhg==xx", ErrMalformedTrailer},
		{"uppercase name", "X-Amz-Checksum-Crc32:NhCmhg==\r\n\r\n", nil},
		{"wrong value", "x-amz-checksum-crc32:AAAAAA==\r\n\r\n", ErrBadDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vr := unsignedTrailerVerifiedRequest(t, "5\r\nhello\r\n0\r\n"+tc.trailer, AlgorithmCRC32)
			rd, err := vr.Reader()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadAll(rd); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestV4ShortTrailerIsMalformed(t *testing.T) {
	for _, trailer := range []string{
		"x-amz-checksum-crc32:NhCmhg==\r\n\r\n",
		"x-amz-checksum-sha1:qvTG",
		"x-amz-checksum-sha1:qvTGHdzF6KLavt4PO0gs2a6pQ00=\r\n",
		"",
	} {
		t.Run(trailer, func(t *testing.T) {
			vr := unsignedTrailerVerifiedRequest(t, "5\r\nhello\r\n0\r\n"+trailer, AlgorithmSHA1)
			rd, err := vr.Reader()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadAll(rd); !errors.Is(err, ErrMalformedTrailer) {
				t.Fatalf("got %v, want ErrMalformedTrailer", err)
			}
		})
	}
}

func TestV4ChecksumRequestErrorsAreClassified(t *testing.T) {
	crc32Trailing, err := NewTrailingChecksumRequest(AlgorithmCRC32)
	if err != nil {
		t.Fatal(err)
	}
	sha1Trailing, err := NewTrailingChecksumRequest(AlgorithmSHA1)
	if err != nil {
		t.Fatal(err)
	}
	crc32Value, err := NewChecksumRequest(AlgorithmCRC32, "NhCmhg==")
	if err != nil {
		t.Fatal(err)
	}
	md5Value, err := NewChecksumRequest(AlgorithmMD5, "XUFAKrxLKna5cZ2REBfFkg==")
	if err != nil {
		t.Fatal(err)
	}
	otherMD5Value, err := NewChecksumRequest(AlgorithmMD5, "1B2M2Y8AsgTpgAmY7PhCfg==")
	if err != nil {
		t.Fatal(err)
	}

	unsigned := func(t *testing.T) *V4VerifiedRequest[struct{}] {
		vr, err := newV4VerifiedRequest(strings.NewReader("hello"), v4VerifiedData[struct{}]{options: parsedXAmzContentSHA256{unsigned: true}})
		if err != nil {
			t.Fatal(err)
		}
		return vr
	}
	trailer := func(t *testing.T) *V4VerifiedRequest[struct{}] {
		return unsignedTrailerVerifiedRequest(t, "", AlgorithmCRC32)
	}

	for _, tc := range []struct {
		name string
		vr   func(*testing.T) *V4VerifiedRequest[struct{}]
		reqs []ChecksumRequest
		want error
	}{
		{"trailing without trailer mode", unsigned, []ChecksumRequest{crc32Trailing}, ErrInvalidChecksumRequest},
		{"two trailing", trailer, []ChecksumRequest{crc32Trailing, sha1Trailing}, ErrInvalidChecksumRequest},
		{"trailing differs from header", trailer, []ChecksumRequest{sha1Trailing}, ErrInvalidChecksumRequest},
		{"trailing and value", trailer, []ChecksumRequest{crc32Value, crc32Trailing}, ErrInvalidChecksumRequest},
		{"header algorithm already has a value", trailer, []ChecksumRequest{crc32Value}, ErrInvalidChecksumRequest},
		{"conflicting values", unsigned, []ChecksumRequest{md5Value, otherMD5Value}, ErrBadDigest},
		{"repeated value", unsigned, []ChecksumRequest{md5Value, md5Value}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.vr(t).Reader(tc.reqs...)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
