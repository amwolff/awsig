package awsig

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestVerifiersRejectMalformedQuery(t *testing.T) {
	for _, v := range []struct {
		name   string
		verify func(*http.Request) error
	}{
		{"V2", func(r *http.Request) error { _, err := NewV2[struct{}](nil).Verify(r, ""); return err }},
		{"V4", func(r *http.Request) error { _, err := NewV4[struct{}](nil, V4Config{}).Verify(r); return err }},
		{"V2V4", func(r *http.Request) error { _, err := NewV2V4[struct{}](nil, V4Config{}).Verify(r, ""); return err }},
	} {
		for _, raw := range []string{"bad=%ZZ", "bad%=x", "ok=1&bad=%", "X-Amz-Algorithm=AWS4-HMAC-SHA256&bad=%ZZ", "AWSAccessKeyId=key&bad=%ZZ"} {
			for _, mode := range []string{"header", "query", "POST"} {
				t.Run(v.name+"/"+raw+"/"+mode, func(t *testing.T) {
					r := httptest.NewRequest("GET", "https://example.com/?"+raw, strings.NewReader("unread body"))
					if mode == "header" {
						r.Header.Set("Authorization", "invalid")
					}
					if mode == "POST" {
						r.Method = "POST"
						r.Header.Set("Content-Type", "multipart/form-data; boundary=test")
					}
					if err := v.verify(r); !errors.Is(err, ErrInvalidRequest) {
						t.Fatalf("got %v, want ErrInvalidRequest", err)
					}
				})
			}
		}
	}
}

func TestRawSemicolonInQuery(t *testing.T) {
	raw := httptest.NewRequest("GET", "https://example.com/key?foo=a;b&x;y=1", nil)
	query, err := parseRequestQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := query["foo"]; len(got) != 1 || got[0] != "a;b" {
		t.Fatalf("foo = %q", got)
	}
	if got := query["x;y"]; len(got) != 1 || got[0] != "1" {
		t.Fatalf("x;y = %q", got)
	}
	// Handlers must see the same pairs that were verified.
	if got := raw.URL.Query(); !reflect.DeepEqual(got, query) {
		t.Fatalf("r.URL.Query() = %q, want %q", got, query)
	}

	// SDKs sign ';' as %3B; a raw ';' must canonicalize identically.
	encoded := httptest.NewRequest("GET", "https://example.com/key?foo=a%3Bb&x%3By=1", nil)
	encodedQuery, err := parseRequestQuery(encoded)
	if err != nil {
		t.Fatal(err)
	}
	v := NewV4[struct{}](nil, V4Config{Service: "s3"})
	if !bytes.Equal(v.canonicalRequestHash(raw, query, []string{"host"}, unsignedPayload), v.canonicalRequestHash(encoded, encodedQuery, []string{"host"}, unsignedPayload)) {
		t.Fatal("raw and encoded ';' canonicalize differently")
	}
}
