package awsig

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeebo/assert"
)

// S3 accepts a presigned URL dated up to 15 minutes ahead of its clock, and refuses one dated 16
// minutes ahead with AccessDenied.
func TestV4PresignedClockSkew(t *testing.T) {
	provider := simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	// The URL is dated 2013-05-24 00:00:00 UTC.
	for _, tc := range []struct {
		now  time.Time
		want error
	}{
		{time.Date(2013, time.May, 23, 23, 50, 0, 0, time.UTC), nil},
		{time.Date(2013, time.May, 23, 23, 45, 0, 0, time.UTC), nil},
		{time.Date(2013, time.May, 23, 23, 44, 0, 0, time.UTC), ErrRequestNotYetValid},
	} {
		v4 := NewV4(provider, V4Config{Region: "us-east-1", Service: "s3"})
		v4.now = func() time.Time { return tc.now }
		req := httptest.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", nil)
		_, err := v4.Verify(req)
		if tc.want == nil {
			assert.NoError(t, err)
		} else {
			assert.That(t, errors.Is(err, tc.want))
		}
	}
}

// S3 doesn't check that a POST policy's date has passed. The verifier allows the same clock skew as
// for other requests.
func TestV4PostClockSkew(t *testing.T) {
	provider := simpleCredentialsProvider{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	// The form is dated 2015-12-29 00:00:00 UTC.
	for _, tc := range []struct {
		now  time.Time
		want error
	}{
		{time.Date(2015, time.December, 28, 23, 50, 0, 0, time.UTC), nil},
		{time.Date(2015, time.December, 28, 23, 44, 0, 0, time.UTC), ErrRequestNotYetValid},
	} {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for _, f := range [][2]string{
			{"key", "user/user1/${filename}"},
			{"X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request"},
			{"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
			{"X-Amz-Date", "20151229T000000Z"},
			{"Policy", "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"},
			{"X-Amz-Signature", "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"},
		} {
			assert.NoError(t, mw.WriteField(f[0], f[1]))
		}
		_, err := mw.CreateFormFile("file", "hello.txt")
		assert.NoError(t, err)
		assert.NoError(t, mw.Close())

		v4 := NewV4(provider, V4Config{Region: "us-east-1", Service: "s3"})
		v4.now = func() time.Time { return tc.now }
		req := httptest.NewRequest(http.MethodPost, "http://sigv4examplebucket.s3.amazonaws.com/", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		_, err = v4.Verify(req)
		if tc.want == nil {
			assert.NoError(t, err)
		} else {
			assert.That(t, errors.Is(err, tc.want))
		}
	}
}
