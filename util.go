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
	// ErrAuthorizationHeaderMalformed indicates the AuthorizationHeaderMalformed error code.
	ErrAuthorizationHeaderMalformed = errors.New("the authorization header that you provided is not valid")
	// ErrBadDigest indicates the BadDigest error code.
	ErrBadDigest = errors.New("the Content-MD5 or checksum value that you specified did not match what the server received")
	// ErrContentLengthWithTransferEncoding indicates that both the Content-Length and Transfer-Encoding headers were provided.
	ErrContentLengthWithTransferEncoding = errors.New("the Content-Length and Transfer-Encoding headers must not both be provided")
	// ErrEntityTooLarge indicates the EntityTooLarge error code.
	ErrEntityTooLarge = errors.New("your proposed upload exceeds the maximum allowed object size")
	// ErrEntityTooSmall indicates the EntityTooSmall error code.
	ErrEntityTooSmall = errors.New("your proposed upload is smaller than the minimum allowed object size")
	// ErrIncompleteBody indicates the IncompleteBody error code.
	ErrIncompleteBody = errors.New("you did not provide the number of bytes specified by the Content-Length HTTP header")
	// ErrInvalidAccessKeyID indicates the InvalidAccessKeyID error code.
	ErrInvalidAccessKeyID = errors.New("the AWS access key ID that you provided does not exist in our records")
	// ErrInvalidArgument indicates the InvalidArgument error code.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrInvalidDateHeader indicates that the Date or X-Amz-Date header is not valid.
	ErrInvalidDateHeader = errors.New("AWS authentication requires a valid Date or x-amz-date header")
	// ErrInvalidDigest indicates the InvalidDigest error code.
	ErrInvalidDigest = errors.New("the Content-MD5 or checksum value that you specified is not valid")
	// ErrInvalidPOSTDate indicates that the X-Amz-Date form field is malformed.
	ErrInvalidPOSTDate = errors.New("the X-Amz-Date form field does not contain a valid date")
	// ErrInvalidPresignedDate indicates that the date provided in a presigned URL is malformed.
	ErrInvalidPresignedDate = errors.New("the X-Amz-Date query parameter does not contain a valid date")
	// ErrInvalidPresignedExpiration indicates that the expiration provided in a presigned URL is not a valid integer.
	ErrInvalidPresignedExpiration = errors.New("the X-Amz-Expires query parameter does not contain a valid integer")
	// ErrInvalidPresignedXAmzContentSHA256 is returned when attempting to read from the body of a presigned request
	// that provided an invalid value for the X-Amz-Content-Sha256 header.
	ErrInvalidPresignedXAmzContentSHA256 = errors.New("the provided 'x-amz-content-sha256' header does not match what was computed")
	// ErrInvalidRequest indicates the InvalidRequest error code.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrInvalidSignature indicates the InvalidSignature error code.
	ErrInvalidSignature = errors.New("the request signature that the server calculated does not match the signature that you provided")
	// ErrInvalidXAmzContentSHA256 indicates that the X-Amz-Content-Sha256 header has an invalid value.
	ErrInvalidXAmzContentSHA256 = errors.New("the x-amz-content-sha256 header does not contain a valid value")
	// ErrInvalidXAmzDecodedContentSHA256 indicates that the X-Amz-Decoded-Content-Length header has an invalid value.
	ErrInvalidXAmzDecodedContentSHA256 = errors.New("the x-amz-decoded-content-length header does not contain a valid integer")
	// ErrMalformedPOSTRequest indicates that a POST request is malformed.
	ErrMalformedPOSTRequest = errors.New("unable to parse multipart form data")
	// ErrMissingAuthenticationToken indicates the MissingAuthenticationToken error code.
	ErrMissingAuthenticationToken = errors.New("the request was not signed")
	// ErrMissingContentLength indicates the MissingContentLength error code.
	ErrMissingContentLength = errors.New("you must provide the Content-Length HTTP header")
	// ErrMissingPOSTPolicy indicates that the POST policy was not provided.
	ErrMissingPOSTPolicy = errors.New("the Policy form field is missing")
	// ErrMissingSecurityHeader indicates the MissingSecurityHeader error code.
	ErrMissingSecurityHeader = errors.New("your request is missing a required header")
	// ErrNegativePresignedExpiration indicates that the expiration provided in a presigned URL is negative integer.
	ErrNegativePresignedExpiration = errors.New("the X-Amz-Expires query parameter is negative")
	// ErrNotImplemented indicates the NotImplemented error code.
	ErrNotImplemented = errors.New("a header that you provided implies functionality that is not implemented")
	// ErrPresignedExpirationTooLarge indicates that the expiration provided in a presigned URL is too large.
	ErrPresignedExpirationTooLarge = errors.New("the X-Amz-Expires query parameter exceeds the maximum of 604800 seconds (7 days)")
	// ErrRequestExpired indicates that the request's expiration date has passed.
	ErrRequestExpired = errors.New("the request has expired")
	// ErrRequestNotYetValid indicates that the request's date is in the future.
	ErrRequestNotYetValid = errors.New("the request is not yet valid")
	// ErrRequestTimeTooSkewed indicates the RequestTimeTooSkewed error code.
	ErrRequestTimeTooSkewed = errors.New("the difference between the request time and the server's time is too large")
	// ErrSignatureDoesNotMatch indicates the SignatureDoesNotMatch error code.
	ErrSignatureDoesNotMatch = errors.New("the request signature that the server calculated does not match the signature that you provided")
	// ErrUnsupportedSignature indicates the UnsupportedSignature error code.
	ErrUnsupportedSignature = errors.New("the provided request is signed with an unsupported STS Token version or the signature version is not supported")
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
// zero values alongside the ErrInvalidAccessKeyID error.
type CredentialsProvider[T any] interface {
	Provide(ctx context.Context, accessKeyID string) (secretAccessKey string, data T, _ error)
}

// PostFormElement represents a single element in a multipart form.
type PostFormElement struct {
	Headers textproto.MIMEHeader
	Value   string
}

func (e PostFormElement) clone() PostFormElement {
	return PostFormElement{
		Headers: textproto.MIMEHeader(http.Header(e.Headers).Clone()),
		Value:   e.Value,
	}
}

// PostForm maps a string key to a list of values.
// It represents a parsed multipart form data.
// Unlike in [url.Values], the keys in [PostForm] are case-insensitive.
type PostForm map[string][]PostFormElement

// Get gets the first value associated with the given key.
// If there are no values associated with the key, Get returns the empty [PostFormElement].
func (f PostForm) Get(key string) PostFormElement {
	v := f[textproto.CanonicalMIMEHeaderKey(key)]
	if len(v) == 0 {
		return PostFormElement{}
	}
	return v[0]
}

// Set sets the key to value.
// It replaces any existing values.
func (f PostForm) Set(key string, value PostFormElement) {
	f[textproto.CanonicalMIMEHeaderKey(key)] = []PostFormElement{value}
}

// Add adds the value to key.
// It appends to any existing values associated with key.
func (f PostForm) Add(key string, value PostFormElement) {
	key = textproto.CanonicalMIMEHeaderKey(key)
	f[key] = append(f[key], value)
}

// Del deletes the values associated with key.
func (f PostForm) Del(key string) {
	delete(f, textproto.CanonicalMIMEHeaderKey(key))
}

// Has checks whether a given key is set.
func (f PostForm) Has(key string) bool {
	_, ok := f[textproto.CanonicalMIMEHeaderKey(key)]
	return ok
}

// Values returns all values associated with the given key.
// The returned slice is not a copy.
func (f PostForm) Values(key string) []PostFormElement {
	return f[textproto.CanonicalMIMEHeaderKey(key)]
}

// Clone returns a copy of f or nil if f is nil.
func (f PostForm) Clone() PostForm {
	if f == nil {
		return nil
	}

	nv := 0
	for _, v := range f {
		nv += len(v)
	}
	ev := make([]PostFormElement, nv)
	f2 := make(PostForm, len(f))
	for k, v := range f {
		if v == nil {
			f2[k] = nil
			continue
		}
		var n int
		for _, vv := range v {
			ev[n] = vv.clone()
			n++
		}
		f2[k] = ev[:n:n]
		ev = ev[n:]
	}
	return f2
}

// FileName returns the filename from the "file" field of the form.
func (f PostForm) FileName() string {
	return f.Get("file").Value
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
		//
		// - MD5 is always computed
		// - SHA-256 is computed if the request has a hashed payload
		Checksums() (map[ChecksumAlgorithm][]byte, error)
	}

	// VerifiedRequest represents a successfully verified AWS Signature
	// Version 4 or AWS Signature Version 2 request.
	VerifiedRequest[T any] interface {
		// AuthData returns data collected while providing credentials
		// via CredentialsProvider. AuthData's type is determined by the
		// generic type parameter T to allow flexibility. For example, a
		// caller that would need to access Access Key ID could call one
		// of the verifiers with T reserving space for Access Key ID,
		// which would be filled by the CredentialsProvider
		// implementation.
		AuthData() T
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
			form.Set(name, PostFormElement{
				Headers: part.Header,
				Value:   part.FileName(),
			})
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
		form.Add(name, PostFormElement{
			Headers: part.Header,
			Value:   string(b),
		})

		if err = part.Close(); err != nil {
			return nil, PostForm{}, err
		}
	}

	return nil, PostForm{}, errors.New("missing file part in multipart form data")
}
