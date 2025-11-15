package awsig

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

const cacheDir = ".cache"

func newRequest(t *testing.T) (bucket string, r *http.Request) {
	req, err := http.NewRequest(http.MethodGet, "https://s3.amazonaws.com/test.txt", nil)
	assert.NoError(t, err)
	return bucket, req
}

func TestErrors(t *testing.T) {
	provider := simpleCredentialsProvider{
		accessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	verifier := NewV2V4(provider, V4Config{
		Region:                 "us-east-1",
		Service:                "s3",
		SkipRegionVerification: false,
	})
	verifier.v2.now = func() time.Time { return now }
	verifier.v4.now = func() time.Time { return now }

	t.Run("ceph/s3-tests", func(t *testing.T) {
		t.Run("test_bucket_create_bad_amz_date_after_today_aws4", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "https://bucket.s3.amazonaws.com/foo", strings.NewReader("bar"))
			req.Header.Set("Authorization", "")
			req.Header.Set("X-Amz-Date", "20300707T215304Z")
		})
		t.Run("test_object_create_bad_date_none_aws2", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "https://bucket.s3.amazonaws.com/foo", strings.NewReader("bar"))
			req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:****************************")
			_, err := verifier.Verify(req, "bucket")
			assert.Equal(t, "AccessDenied", awsigErrorToCode(err))
		})
	})
}

func equalOutcome[T any](t *testing.T, us *V2V4[T], vhostedBucket string, req *http.Request) {
	fpath := filepath.Join(cacheDir, strings.ReplaceAll(t.Name(), "/", "_"))
	_, err := us.Verify(req, vhostedBucket)
	ourCode := awsigErrorToCode(err)

	theirCode, err := os.ReadFile(fpath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			assert.NoError(t, err)
		}
		// otherwise, we're going to go the slow path below
	} else {
		assert.Equal(t, string(theirCode), ourCode)
	}

	type errorResponse struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}

	resp, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	var theirResponse errorResponse
	assert.NoError(t, xml.NewDecoder(resp.Body).Decode(&theirResponse))

	theirCode = []byte(theirResponse.Code)
	assert.NoError(t, os.MkdirAll(cacheDir, 0755))
	assert.NoError(t, os.WriteFile(fpath, theirCode, 0644)) // cache for next time

	assert.Equal(t, theirResponse.Code, ourCode)

	t.Logf("their msg: %q, our msg: %q", theirResponse.Message, errors.Unwrap(err).Error())
}

func awsigErrorToCode(err error) string {
	if errors.Is(err, ErrAccessDenied) {
		return "AccessDenied"
	}
	// TODO(amwolff): map more errors to codes
	return ""
}
