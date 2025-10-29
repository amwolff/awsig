package awsig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// (1) Implement awsig.CredentialsProvider:
type (
	MyAuthData struct {
		AccessKeyID string
	}
	MyCredentialsProvider struct {
		secretAccessKeys map[string]string
	}
)

func (p *MyCredentialsProvider) Provide(_ context.Context, accessKeyID string) (secretAccessKey string, _ MyAuthData, _ error) {
	var data MyAuthData

	secretAccessKey, ok := p.secretAccessKeys[accessKeyID]
	if !ok {
		return "", data, ErrInvalidAccessKeyID
	}

	data.AccessKeyID = accessKeyID

	return secretAccessKey, data, nil
}

func NewMyCredentialsProvider() *MyCredentialsProvider {
	return &MyCredentialsProvider{
		secretAccessKeys: map[string]string{
			"AKIAIOSFODNN7EXAMPLE": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}
}

func Example() {
	// (2) Create a combined V2/V4 verifier for S3 in us-east-1.
	// You can also create a standalone V2-only or V4-only verifier:
	v2v4 := NewV2V4(NewMyCredentialsProvider(), V4Config{
		Region:  "us-east-1",
		Service: "s3",
	})

	h := func(w http.ResponseWriter, r *http.Request) {
		// (3) Verify the incoming request:
		vr, err := v2v4.Verify(r, "virtual-hosted-bucket-indication-for-v2")
		if err != nil {
			errToHTTPError(w, err)
			return
		}
		fmt.Printf("verified the incoming request with Access Key ID=%s\n", vr.AuthData().AccessKeyID)
		// (4) If the request is a multipart/form-data POST, you can access the parsed form values:
		if vr.PostForm() != nil {
			fmt.Println("this request is a multipart/form-data POST")
		}
		//
		// Important: if you intend to read the body, use vr.Reader() instead of r.Body.
		//
		// (5) Declare which checksums you want to be verified/computed:
		var reqs []ChecksumRequest
		{
			req, err := NewChecksumRequest(AlgorithmSHA1, "CgqfKmdylCVXq1NV12r0Qvj2XgE=")
			if err != nil {
				errToHTTPError(w, err)
				return
			}
			reqs = append(reqs, req)
		}
		if r.Header.Get("x-amz-trailer") == "x-amz-checksum-crc32" {
			req, err := NewTrailingChecksumRequest(AlgorithmCRC32)
			if err != nil {
				errToHTTPError(w, err)
				return
			}
			reqs = append(reqs, req)
		}
		// (6) Read the body. Notes:
		//
		// - requested checksums are verified automatically
		// - if the request includes a trailing checksum header, at least one checksum must be requested
		// - if not explicitly requested:
		//   - MD5 is always computed and available after reading
		//   - SHA256 is computed and available after reading, depending on the request type
		body, err := vr.Reader(reqs...)
		if err != nil {
			errToHTTPError(w, err)
			return
		}

		_, err = io.Copy(w, body) // copy or do something else with the body
		if err != nil {
			errToHTTPError(w, err)
			return
		}

		// (7) Access computed/verified checksums as needed:
		checksums, err := body.Checksums()
		if err != nil {
			errToHTTPError(w, err)
			return
		}
		for algo, sum := range checksums {
			fmt.Printf("%s of the received content is %x\n", algo, sum)
		}

		// Perform additional application logic as needed…
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "https://bucket.s3-compatible.provider.com/object.txt", strings.NewReader("Hello, World!"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20000101/us-east-1/s3/aws4_request, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date, Signature=f7e9ff55dfc3b67c3ad92147a3056687e986e907e36f7971eaea693065bf999e")
	req.Header.Set("Content-Length", "13")
	req.Header.Set("X-Amz-Content-Sha256", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
	req.Header.Set("X-Amz-Date", "20000101T000000Z")

	serveHTTPAt(v2v4, h, rec, req, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

	fmt.Println(rec.Body.String())
	// Unordered output:
	// verified the incoming request with Access Key ID=AKIAIOSFODNN7EXAMPLE
	// md5 of the received content is 65a8e27d8879283831b664bd8b7f0ad4
	// sha1 of the received content is 0a0a9f2a6772942557ab5355d76af442f8f65e01
	// sha256 of the received content is dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
	// Hello, World!
}

func errToHTTPError(w http.ResponseWriter, _ error) {
	defaultCode := http.StatusInternalServerError
	// TODO: match awsig errors to HTTP codes
	http.Error(w, http.StatusText(defaultCode), defaultCode)
}

func serveHTTPAt[T any](v *V2V4[T], h http.HandlerFunc, w http.ResponseWriter, r *http.Request, t time.Time) {
	prev2 := v.v2.now
	prev4 := v.v4.now

	now := func() time.Time { return t }

	v.v2.now = now
	v.v4.now = now

	h(w, r)

	v.v2.now = prev2
	v.v4.now = prev4
}
