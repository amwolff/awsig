package awsig

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrAccessDenied indicates the AccessDenied error code.
	ErrAccessDenied = errors.New("access denied")
	// ErrAuthorizationHeaderMalformed indicates the AuthorizationHeaderMalformed error code.
	ErrAuthorizationHeaderMalformed = errors.New("the authorization header that you provided is not valid")
	// ErrAuthorizationQueryParametersError indicates the AuthorizationQueryParametersError error code.
	ErrAuthorizationQueryParametersError = errors.New("the authorization query parameters that you provided are not valid")
	// ErrBadDigest indicates the BadDigest error code.
	ErrBadDigest = errors.New("the Content-MD5 or checksum value that you specified did not match what the server received")
	// ErrEntityTooLarge indicates the EntityTooLarge error code.
	ErrEntityTooLarge = errors.New("your proposed upload exceeds the maximum allowed object size")
	// ErrEntityTooSmall indicates the EntityTooSmall error code.
	ErrEntityTooSmall = errors.New("your proposed upload is smaller than the minimum allowed object size")
	// ErrIncompleteBody indicates the IncompleteBody error code.
	ErrIncompleteBody = errors.New("you did not provide the number of bytes specified by the Content-Length HTTP header")
	// ErrInvalidArgument indicates the InvalidArgument error code.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrInvalidDigest indicates the InvalidDigest error code.
	ErrInvalidDigest = errors.New("the Content-MD5 or checksum value that you specified is not valid")
	// ErrInvalidRequest indicates the InvalidRequest error code.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrInvalidSignature indicates the InvalidSignature error code.
	ErrInvalidSignature = errors.New("the request signature that the server calculated does not match the signature that you provided")
	// ErrMissingAuthenticationToken indicates the MissingAuthenticationToken error code.
	ErrMissingAuthenticationToken = errors.New("the request was not signed")
	// ErrMissingContentLength indicates the MissingContentLength error code.
	ErrMissingContentLength = errors.New("you must provide the Content-Length HTTP header")
	// ErrMissingSecurityHeader indicates the MissingSecurityHeader error code.
	ErrMissingSecurityHeader = errors.New("your request is missing a required header")
	// ErrRequestTimeTooSkewed indicates the RequestTimeTooSkewed error code.
	ErrRequestTimeTooSkewed = errors.New("the difference between the request time and the server's time is too large")
	// ErrSignatureDoesNotMatch indicates the SignatureDoesNotMatch error code.
	ErrSignatureDoesNotMatch = errors.New("the request signature that the server calculated does not match the signature that you provided")
	// ErrUnsupportedSignature indicates the UnsupportedSignature error code.
	ErrUnsupportedSignature = errors.New("the provided request is signed with an unsupported STS Token version or the signature version is not supported")

	// ErrInvalidAccessKeyID indicates the InvalidAccessKeyID error code.
	ErrInvalidAccessKeyID = errors.New("the AWS access key ID that you provided does not exist in our records")

	// ErrNotImplemented indicates the NotImplemented error code.
	ErrNotImplemented = errors.New("a header that you provided implies functionality that is not implemented")
)

const (
	xAmzHeaderPrefix = "x-amz-"

	headerAuthorization     = "authorization"
	headerContentMD5        = "content-md5"
	headerContentType       = "content-type"
	headerDate              = "date"
	headerXAmzContentSha256 = xAmzHeaderPrefix + "content-sha256"
	headerXAmzDate          = xAmzHeaderPrefix + "date"

	formNamePolicy = "Policy"

	timeFormatISO8601  = "20060102T150405Z"
	timeFormatYYYYMMDD = "20060102"

	maxRequestTimeSkew = 15 * time.Minute
)

var httpTimeFormats = []string{
	http.TimeFormat,
	"Mon, 02 Jan 2006 15:04:05 -0700",
	time.RFC850,
	time.ANSIC,
}

var errMessageTooLarge = errors.New("message too large")

// CredentialsProvider is the interface that all users of this package
// must implement. Provide is called by signature verifiers. If the
// given accessKeyID is unknown to the implementation, it should return
// an empty Secret Access Key and the ErrInvalidAccessKeyID error.
type CredentialsProvider interface {
	Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, _ error)
}

type (
	// Reader is an io.Reader to be used to read the body of a verified
	// request with optional checksum computation and auto-verification.
	Reader interface {
		io.Reader
		// Checksums returns computed checksums of the read data.
		// Checksums are only available after reaching EOF.
		// If called before reaching EOF, it returns an error.
		//
		// If not previously requested:
		// 	- MD5 is always computed
		// 	- SHA-256 is computed if the request has a hashed payload
		Checksums() (map[ChecksumAlgorithm][]byte, error)
	}

	// VerifiedRequest represents a successfully verified AWS Signature
	// Version 4 or AWS Signature Version 2 request.
	VerifiedRequest interface {
		// PostForm returns the parsed multipart form data if the
		// request is a POST with "multipart/form-data" Content-Type.
		PostForm() PostForm
		// Reader returns a Reader to read the body of the verified
		// request. Reader can be called multiple times, but only the
		// first call can request checksums. Checksum requests must have
		// distinct algorithms. If the request includes a trailing
		// checksum header, at least one checksum must be requested.
		Reader(...ChecksumRequest) (Reader, error)
	}
)

type nestedError struct {
	outer error
	inner error
}

func (e *nestedError) Error() string {
	return fmt.Sprintf("%v: %v", e.outer, e.inner)
}

func (e *nestedError) Unwrap() error {
	return e.inner
}

func (e *nestedError) Is(target error) bool {
	if e.outer == target {
		return true
	}
	return errors.Is(e.inner, target)
}

func nestError(outer error, format string, a ...any) *nestedError {
	return &nestedError{
		outer: outer,
		inner: fmt.Errorf(format, a...),
	}
}

func parseTimeWithFormats(value string, formats []string) (time.Time, error) {
	var (
		t   time.Time
		err error
	)
	for _, layout := range formats {
		t, err = time.Parse(layout, value)
		if err == nil {
			return t, nil
		}
	}
	return t, err
}

func timeOutOfBounds(now func() time.Time, b1, b2 time.Time) bool {
	if b1.After(b2) {
		b1, b2 = b2, b1
	}
	if n := now(); n.Before(b1) || n.After(b2) {
		return true
	}
	return false
}

func timeSkewExceeded(now func() time.Time, t time.Time, skew time.Duration) bool {
	return timeOutOfBounds(now, t.Add(-skew), t.Add(skew))
}

func uriEncode(value string, path bool) string {
	encoded := url.QueryEscape(value)
	oldnews := []string{"+", "%20"}

	if path {
		oldnews = append(oldnews, "%2F", "/")
	}

	return strings.NewReplacer(oldnews...).Replace(encoded)
}

type hashBuilder struct {
	h hash.Hash
}

func (b *hashBuilder) Write(p []byte) (int, error) {
	return b.h.Write(p)
}

func (b *hashBuilder) WriteByte(c byte) error {
	_, err := b.h.Write([]byte{c})
	return err
}

func (b *hashBuilder) WriteString(s string) (int, error) {
	return b.h.Write([]byte(s))
}

func (b *hashBuilder) Sum() []byte {
	return b.h.Sum(nil)
}

func newHashBuilder(h func() hash.Hash) *hashBuilder {
	return &hashBuilder{
		h: h(),
	}
}

// PostFormElement represents a single element in a multipart form.
type PostFormElement struct {
	Value   string
	Headers textproto.MIMEHeader
}

// PostForm represents a parsed multipart form data.
type PostForm map[string][]PostFormElement

// FileName returns the filename from the "file" field of the form.
func (f PostForm) FileName() string {
	v, _ := f.Get("file")
	return v
}

// Add adds a new value to the form field with the given key.
func (f PostForm) Add(key, value string, headers textproto.MIMEHeader) {
	k := textproto.CanonicalMIMEHeaderKey(key)
	f[k] = append(f[k], PostFormElement{
		Value:   value,
		Headers: headers,
	})
}

// Set sets the form field to the given value, replacing any existing
// values.
func (f PostForm) Set(key string, value string, headers textproto.MIMEHeader) {
	k := textproto.CanonicalMIMEHeaderKey(key)
	f[k] = []PostFormElement{{
		Value:   value,
		Headers: headers,
	}}
}

// Get returns the first value and headers for the given key.
func (f PostForm) Get(key string) (string, textproto.MIMEHeader) {
	if f == nil {
		return "", nil
	}
	v := f[textproto.CanonicalMIMEHeaderKey(key)]
	if len(v) == 0 {
		return "", nil
	}
	return v[0].Value, v[0].Headers
}

// Values returns all values and headers for the given key.
func (f PostForm) Values(key string) ([]string, []textproto.MIMEHeader) {
	if f == nil {
		return nil, nil
	}
	v := f[textproto.CanonicalMIMEHeaderKey(key)]
	vals := make([]string, 0, len(v))
	hdrs := make([]textproto.MIMEHeader, 0, len(v))
	for _, e := range v {
		vals = append(vals, e.Value)
		hdrs = append(hdrs, e.Headers)
	}
	return vals, hdrs
}

// Has reports whether the form contains the given key.
func (f PostForm) Has(key string) bool {
	if f == nil {
		return false
	}
	_, ok := f[textproto.CanonicalMIMEHeaderKey(key)]
	return ok
}

var errLimitReached = errors.New("limitedReader: limit reached")

func limitReader(r io.Reader, n int64) *limitedReader {
	return &limitedReader{
		r:       r,
		n:       n,
		enabled: true,
	}
}

type limitedReader struct {
	r       io.Reader
	n       int64
	enabled bool
}

func (l *limitedReader) Read(p []byte) (n int, err error) {
	if !l.enabled {
		return l.r.Read(p)
	}
	if l.n <= 0 {
		return 0, errors.Join(io.EOF, errLimitReached)
	}

	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}

	n, err = l.r.Read(p)
	l.n -= int64(n)

	return n, err
}

func (l *limitedReader) toggle() {
	l.enabled = !l.enabled
}

func parseMultipartFormUntilFile(r io.Reader, boundary string) (io.ReadCloser, PostForm, error) {
	if boundary == "" {
		return nil, nil, http.ErrMissingBoundary
	}

	lr := limitReader(r, 20000) // the 20KB limit is mentioned in https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
	mr := multipart.NewReader(lr, boundary)

	form := make(PostForm)
	for {
		part, err := mr.NextPart()
		if err != nil {
			if errors.Is(err, errLimitReached) {
				err = errMessageTooLarge
			} else if errors.Is(err, io.EOF) {
				break
			}
			return nil, PostForm{}, err
		}

		name := part.FormName()

		if name == "file" {
			lr.toggle() // stop limiting the reader as we reached the file part
			form.Set(name, part.FileName(), part.Header)
			return part, form, nil
		}

		b, err := io.ReadAll(part)
		if err != nil {
			if errors.Is(err, errLimitReached) {
				err = errMessageTooLarge
			}
			if errClose := part.Close(); errClose != nil {
				err = errors.Join(err, errClose)
			}
			return nil, PostForm{}, err
		}
		form.Add(name, string(b), part.Header)

		if err = part.Close(); err != nil {
			return nil, PostForm{}, err
		}
	}

	return nil, PostForm{}, errors.New("missing file part in multipart form data")
}
