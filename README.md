awsig is a Go library implementing server-side verification of AWS
Signature Version 4 (SigV4) and AWS Signature Version 2 (SigV2) meant
for building AWS-compatible services.

## compatibility

|       | regular signed requests | UNSIGNED-PAYLOAD | STREAMING-UNSIGNED-PAYLOAD-TRAILER | STREAMING-AWS4-HMAC-SHA256-PAYLOAD | STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER | STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD | STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER | presigned | presigned (POST) |
|:-----:|:-----------------------:|:----------------:|:----------------------------------:|:----------------------------------:|:------------------------------------------:|:----------------------------------------:|:------------------------------------------------:|:---------:|:----------------:|
| SigV2 |            ✓            |        n/a       |                 n/a                |                 n/a                |                     n/a                    |                    n/a                   |                        n/a                       |     ✓     |         ✓        |
| SigV4 |            ✓            |         ✓        |                  ✓                 |                  ✓                 |                      ✓                     |              _unimplemented_             |                  _unimplemented_                 |     ✓     |         ✓        |

This package was written with S3 and certain security and performance
characteristics in mind, but it should work for other service clones as
well.

### TODO

- [x] verify the returned errors (error codes) with the real AWS (preferably S3) or a close clone, like Ceph
- [ ] do shallow test runs with all publicly available AWS SDKs
    - [ ] SDKs act differently with and without TLS and with different checksum options

## example usage

```go
package …

import (
	…
	"github.com/amwolff/awsig"
)

// (1) Implement awsig.CredentialsProvider:
type MyCredentialsProvider struct {
	secretAccessKeys map[string]string
}

func (p *MyCredentialsProvider) Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error) {
	secretAccessKey, ok := p.secretAccessKeys[accessKeyID]
	if !ok {
		return "", awsig.ErrInvalidAccessKeyID
	}
	return secretAccessKey, nil
}

func NewMyCredentialsProvider() *MyCredentialsProvider {
	return &MyCredentialsProvider{
		secretAccessKeys: map[string]string{
			"AKIAIOSFODNN7EXAMPLE": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}
}

// (2) Create a combined V2/V4 verifier for S3 in us-east-1.
// You can also create a standalone V2-only or V4-only verifier:
v2v4 := awsig.NewV2V4(NewMyCredentialsProvider(), awsig.V4Config{
	Region:  "us-east-1",
	Service: "s3",
})

func …(w http.ResponseWriter, r *http.Request) {
	// (3) Verify the incoming request:
	vr, err := v2v4.Verify(r, "virtual-hosted-bucket-indication-for-v2")
	if err != nil {
		…
	}
	// (4) If the request is a multipart/form-data POST, you can access the parsed form values:
	form := vr.PostForm()
	//
	// Important: if you intend to read the body, use vr.Reader() instead of r.Body.
	//
	// (5) Declare which checksums you want to be verified/computed:
	sha1Req, err := awsig.NewChecksumRequest(awsig.AlgorithmSHA1, "ziEPrgmMDfQDTAAAQZuYfMjU4uc=")
	if err != nil {
		…
	}
	crc32Req, err := awsig.NewTrailingChecksumRequest(awsig.AlgorithmCRC32)
	if err != nil {
		…
	}
	// (6) Read the body. Notes:
	//
	// - requested checksums are verified automatically
	// - if the request includes a trailing checksum header, at least one checksum must be requested
	// - if not explicitly requested:
	//   - MD5 is always computed and available after reading
	//   - SHA256 is computed and available after reading, depending on the request type
	body, err := vr.Reader(sha1Req, crc32Req)
	if err != nil {
		…
	}

	_, err = io.Copy(…, body) // copy or do something else with the body
	if err != nil {
		…
	}

	// (7) Access computed/verified checksums as needed:
	checksums, err := body.Checksums()
	if err != nil {
		…
	}
	for algo, sum := range checksums {
		log.Printf("%s: %x", algo, sum)
	}

	// Perform additional application logic as needed…
}
```

A complete working example can be found in `awsig_test.go` (`Example`).
