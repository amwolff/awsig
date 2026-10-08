package awsig

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMultipartParseErrorsRemainVisible(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("policy", strings.Repeat("x", 21000)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		verify func(*http.Request) error
	}{
		{"V2", func(r *http.Request) error { _, err := NewV2[struct{}](nil).Verify(r, ""); return err }},
		{"V4", func(r *http.Request) error { _, err := NewV4[struct{}](nil, V4Config{}).Verify(r); return err }},
		{"V2V4", func(r *http.Request) error { _, err := NewV2V4[struct{}](nil, V4Config{}).Verify(r, ""); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://example.com/", bytes.NewReader(body.Bytes()))
			r.Header.Set("Content-Type", mw.FormDataContentType())
			err := tc.verify(r)
			if !errors.Is(err, ErrMalformedPOSTRequest) {
				t.Fatalf("lost public error: %v", err)
			}
			if !errors.Is(err, ErrMessageTooLarge) {
				t.Fatalf("lost size-limit error: %v", err)
			}
		})
	}
}
