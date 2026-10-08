package awsig

import (
	"bytes"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestV2SubresourcePolicy(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	provider := simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"}
	for _, selector := range []string{"defaultObjectAcl", "storageClass", "encryption", "legal-hold", "retention", "intelligent-tiering", "ownershipControls", "policyStatus", "publicAccessBlock"} {
		supported := selector == "defaultObjectAcl" || selector == "storageClass"
		for _, presigned := range []bool{false, true} {
			for _, combined := range []bool{false, true} {
				for _, signSelector := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/presigned=%t/combined=%t/signed=%t", selector, presigned, combined, signSelector), func(t *testing.T) {
						v := NewV2V4(provider, V4Config{})
						v.v2.now = func() time.Time { return now }
						date := now.Format(http.TimeFormat)
						q := url.Values{selector: {"test"}}
						if presigned {
							date = strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
							q.Set(queryAWSAccessKeyId, "key")
							q.Set(queryExpires, date)
						}
						// Sign independently of the verifier's subresource map. Both a signer
						// including the selector and one omitting it must fail for blocked APIs.
						resource := "/bucket/key"
						if signSelector {
							resource += "?" + selector + "=test"
						}
						signature := calculateSignatureV2("GET\n\n\n"+date+"\n"+resource, "secret")
						if presigned {
							q.Set(querySignature, signature.String())
						}
						r := httptest.NewRequest("GET", "https://example.com/bucket/key?"+q.Encode(), nil)
						if !presigned {
							r.Header.Set("Date", date)
							r.Header.Set("Authorization", "AWS key:"+signature.String())
						}
						var err error
						if combined {
							_, err = v.Verify(r, "")
						} else {
							_, err = v.v2.Verify(r, "")
						}
						var want error
						if !supported {
							want = ErrInvalidRequest
						} else if !signSelector {
							want = ErrSignatureDoesNotMatch
						}
						if !errors.Is(err, want) {
							t.Fatalf("got %v, want %v", err, want)
						}
						if !supported && !strings.Contains(err.Error(), "requires SigV4") {
							t.Fatalf("missing migration guidance: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestV2SubresourcePolicyPOST(t *testing.T) {
	now := time.Date(2026, time.September, 23, 0, 0, 0, 0, time.UTC)
	for _, selector := range []string{"encryption", "legal-hold", "retention", "intelligent-tiering", "ownershipControls", "policyStatus", "publicAccessBlock"} {
		for _, version := range []int{2, 4} {
			for _, combined := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/v%d/combined=%t", selector, version, combined), func(t *testing.T) {
					r := postRequest(t, version, now)
					r.URL.RawQuery = selector
					v := NewV2V4(simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"}, V4Config{Region: "us-east-1", Service: "s3"})
					v.v4.now = func() time.Time { return now }
					var err error
					switch {
					case combined:
						_, err = v.Verify(r, "")
					case version == 2:
						_, err = v.v2.Verify(r, "")
					default:
						_, err = v.v4.Verify(r)
					}
					var want error
					if version == 2 {
						want = ErrInvalidRequest
					}
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
				})
			}
		}
	}
}

func postRequest(t *testing.T, version int, now time.Time) *http.Request {
	t.Helper()
	date := now.UTC().Format(timeFormatISO8601)
	sc := scope{date: date[:8], region: "us-east-1", service: "s3"}
	form := map[string]string{"policy": "e30="}
	if version == 2 {
		form[queryAWSAccessKeyId] = "key"
		form[querySignature] = NewV2[string](nil).calculatePostSignature(form["policy"], "secret").String()
	} else {
		v4 := NewV4[string](nil, V4Config{Region: "us-east-1", Service: "s3"})
		form[queryXAmzAlgorithm] = "AWS4-HMAC-SHA256"
		form[queryXAmzCredential] = "key/" + sc.String()
		form[queryXAmzDate] = date
		form[queryXAmzSignature] = v4.calculatePostSignature(signatureV4Data{scope: sc, digest: []byte(form["policy"])}, "secret").String()
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range form {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := mw.CreateFormFile("file", "test.txt"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://example.com/bucket", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}
