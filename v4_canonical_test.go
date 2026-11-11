package awsig

import (
	"net/http/httptest"
	"testing"

	"github.com/zeebo/assert"
)

func TestCanonicalQuery(t *testing.T) {
	v := new(V4[struct{}])
	for _, tc := range []struct{ query, want string }{
		{"", ""},
		{"a=1&a=2", "a=1&a=2"},
		{"a=2&a=1", "a=1&a=2"},
		{"a=0&b=2&b=1", "a=0&b=1&b=2"},
		{"z=1&%C3%A9=2", "%C3%A9=2&z=1"},
		{"a=z&a=%C3%A9", "a=%C3%A9&a=z"},
		{"a-=1&a=2", "a=2&a-=1"},
		{"acl&prefix=a+b", "acl=&prefix=a%20b"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://example.com/?"+tc.query, nil)
			query := r.URL.Query()
			got := v.canonicalRequestHash(r, query, []string{"host"}, unsignedPayload)
			want := sha256Hash([]byte("GET\n/\n" + tc.want + "\nhost:example.com\n\nhost\nUNSIGNED-PAYLOAD"))
			assert.Equal(t, want, got)
			// Sorting the values must not reorder the caller's query.
			assert.DeepEqual(t, r.URL.Query(), query)
		})
	}
}

func TestCanonicalHeaders(t *testing.T) {
	v := new(V4[struct{}])
	for _, tc := range []struct {
		name   string
		values []string
		want   string
	}{
		{"repeated", []string{"first", "second"}, "first,second"},
		{"whitespace", []string{"  a  b  c  "}, "a b c"},
		{"tab", []string{"a\tb"}, "a b"},
		{"spaces and tabs", []string{"a \t\t b"}, "a b"},
		{"non-breaking space", []string{"a b"}, "a b"},
		{"surrounding whitespace", []string{"\t foo \t"}, "foo"},
		{"combined", []string{" a  b ", " c "}, "a b,c"},
		{"empty value", []string{"", "c"}, ",c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "https://example.com/", nil)
			for _, v := range tc.values {
				r.Header.Add("X-Amz-Meta-Test", v)
			}
			original := r.Header.Clone()
			got := v.canonicalRequestHash(r, nil, []string{"host", "x-amz-meta-test"}, unsignedPayload)
			want := sha256Hash([]byte("GET\n/\n\nhost:example.com\nx-amz-meta-test:" + tc.want + "\n\nhost;x-amz-meta-test\nUNSIGNED-PAYLOAD"))
			assert.Equal(t, want, got)
			assert.DeepEqual(t, original, r.Header)
		})
	}
}
