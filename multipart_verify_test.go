package awsig

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeebo/assert"
)

func TestMultipartParseErrorsRemainVisible(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	assert.NoError(t, mw.WriteField("policy", strings.Repeat("x", 21000)))
	assert.NoError(t, mw.Close())
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
			assert.That(t, errors.Is(err, ErrMalformedPOSTRequest))
			assert.That(t, errors.Is(err, ErrMessageTooLarge))
		})
	}
}
