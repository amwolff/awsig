package awsig

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestV2BucketPath(t *testing.T) {
	p := simpleCredentialsProvider{accessKeyID: "key", secretAccessKey: "secret"}
	now := dummyNow(2026, time.September, 23, 0, 0, 0)
	for _, tc := range []struct{ path, bucket, canonical string }{
		{"/bucket", "", "/bucket/"},
		{"/bucket/", "", "/bucket/"},
		{"/bucket/key", "", "/bucket/key"},
		{"/", "", "/"},
		{"/", "bucket", "/bucket/"},
		{"/key", "bucket", "/bucket/key"},
	} {
		for _, presigned := range []bool{false, true} {
			for _, combined := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/bucket=%s/presigned=%t/combined=%t", tc.path, tc.bucket, presigned, combined), func(t *testing.T) {
					v := NewV2V4(p, V4Config{})
					v.v2.now = now
					r := httptest.NewRequest("GET", "http://localhost"+tc.path, nil)
					date := now().UTC().Format(http.TimeFormat)
					if presigned {
						date = strconv.FormatInt(now().Add(time.Hour).Unix(), 10)
					}
					sig := calculateSignatureV2("GET\n\n\n"+date+"\n"+tc.canonical, "secret")
					if presigned {
						r.URL.RawQuery = url.Values{"AWSAccessKeyId": {"key"}, "Expires": {date}, "Signature": {sig.String()}}.Encode()
					} else {
						r.Header.Set("Date", date)
						r.Header.Set("Authorization", "AWS key:"+sig.String())
					}
					var err error
					if combined {
						_, err = v.Verify(r, tc.bucket)
					} else {
						_, err = v.v2.Verify(r, tc.bucket)
					}
					if err != nil {
						t.Fatalf("path %q signed as %q: %v", tc.path, tc.canonical, err)
					}
				})
			}
		}
	}
}
