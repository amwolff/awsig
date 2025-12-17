package awsig

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	queryAWSAccessKeyId = "AWSAccessKeyId" //nolint:revive
	queryExpires        = "Expires"
	querySignature      = "Signature"
)

type v2Reader struct {
	ir        *integrityReader
	integrity expectedIntegrity
}

func (r *v2Reader) Read(p []byte) (n int, err error) {
	if n, err = r.ir.Read(p); errors.Is(err, io.EOF) {
		if err := r.ir.verify(r.integrity); err != nil {
			return n, nestError(ErrBadDigest, "verify failed: %w", err)
		}
	}
	return n, err
}

func (r *v2Reader) Checksums() (map[ChecksumAlgorithm][]byte, error) {
	return r.ir.checksums()
}

type v2VerifiedData[T any] struct {
	authData T
}

// V2VerifiedRequest implements VerifiedRequest for AWS Signature
// Version 2.
type V2VerifiedRequest[T any] struct {
	form   PostForm
	data   v2VerifiedData[T]
	source io.Reader

	wrapped *v2Reader

	algorithms []ChecksumAlgorithm
	integrity  expectedIntegrity
}

func newV2VerifiedRequestWithForm[T any](source io.Reader, data v2VerifiedData[T], form PostForm) (*V2VerifiedRequest[T], error) {
	return &V2VerifiedRequest[T]{
		form:      form,
		data:      data,
		source:    source,
		integrity: make(expectedIntegrity),
	}, nil
}

func newV2VerifiedRequest[T any](source io.Reader, data v2VerifiedData[T]) (*V2VerifiedRequest[T], error) {
	return newV2VerifiedRequestWithForm(source, data, nil)
}

// AuthData implements VerifiedRequest.
func (vr *V2VerifiedRequest[T]) AuthData() T {
	return vr.data.authData
}

// PostForm implements VerifiedRequest.
func (vr *V2VerifiedRequest[T]) PostForm() PostForm {
	return vr.form
}

func (vr *V2VerifiedRequest[T]) addAlgorithm(algorithm ChecksumAlgorithm) error {
	if slices.Contains(vr.algorithms, algorithm) {
		return errors.New("algorithm already added")
	}
	vr.algorithms = append(vr.algorithms, algorithm)
	return nil
}

func (vr *V2VerifiedRequest[T]) requestChecksum(req ChecksumRequest) error {
	if !req.valid() {
		return fmt.Errorf("uninitialized request")
	}
	if req.trailing {
		return fmt.Errorf("could not add %s: trailing checksums are not supported in V2", req.algorithm)
	}
	if err := vr.addAlgorithm(req.algorithm); err != nil {
		return fmt.Errorf("could not add %s: %w", req.algorithm, err)
	}
	vr.integrity.setDecoded(req.algorithm, req.value)
	return nil
}

func (vr *V2VerifiedRequest[T]) requestChecksums(reqs []ChecksumRequest) error {
	for i, req := range reqs {
		if err := vr.requestChecksum(req); err != nil {
			return fmt.Errorf("could not process request %d: %w", i, err)
		}
	}
	return nil
}

// Reader implements VerifiedRequest.
func (vr *V2VerifiedRequest[T]) Reader(reqs ...ChecksumRequest) (Reader, error) {
	if vr.wrapped != nil {
		if len(reqs) > 0 {
			return nil, errors.New("cannot request additional checksums after Reader has been requested")
		}
		return vr.wrapped, nil
	}

	if err := vr.requestChecksums(reqs); err != nil {
		return nil, err
	}

	vr.wrapped = &v2Reader{
		ir:        newIntegrityReader(vr.source, vr.algorithms),
		integrity: vr.integrity,
	}

	return vr.wrapped, nil
}

// V2 implements AWS Signature Version 2 verification.
type V2[T any] struct {
	provider CredentialsProvider[T]
	now      func() time.Time
}

// NewV2 creates a new V2 with the given provider.
func NewV2[T any](provider CredentialsProvider[T]) *V2[T] {
	return &V2[T]{
		provider: provider,
		now:      time.Now,
	}
}

func (v2 *V2[T]) parseTime(headers http.Header) (string, time.Time, error) {
	var alt string

	if v := headers.Values(headerDate); len(v) > 0 {
		alt = v[0]
	}

	if v := headers.Values(headerXAmzDate); len(v) > 0 {
		if v[0] == "" {
			return "", time.Time{}, ErrInvalidDateHeader
		}

		parsed, err := parseTimeWithFormats(v[0], httpTimeFormats)
		if err != nil {
			return "", time.Time{}, nestError(
				ErrInvalidDateHeader,
				"parsing time with formats failed: %w", err,
			)
		}
		return alt, parsed, nil
	}
	if alt != "" {
		parsed, err := parseTimeWithFormats(alt, httpTimeFormats)
		if err != nil {
			return "", time.Time{}, nestError(
				ErrInvalidDateHeader,
				"parsing time with formats failed: %w", err,
			)
		}
		return alt, parsed, nil
	}
	return "", time.Time{}, ErrInvalidDateHeader // no date header at all
}

type v2ParsedAuthorization struct {
	accessKeyID string
	signature   signatureV2
}

func (v2 *V2[T]) parseAuthorization(rawAuthorization string) (v2ParsedAuthorization, error) {
	rawAlgorithm, afterAlgorithm, ok := strings.Cut(rawAuthorization, " ")
	if !ok {
		return v2ParsedAuthorization{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected parts", headerAuthorization,
		)
	}

	if rawAlgorithm != "AWS" {
		return v2ParsedAuthorization{}, nestError(
			ErrUnsupportedSignature,
			"the %s header does not contain a valid signing algorithm", headerAuthorization,
		)
	}

	accessKeyID, rawSignature, ok := strings.Cut(afterAlgorithm, ":")
	if !ok {
		return v2ParsedAuthorization{}, nestError(
			ErrAuthorizationHeaderMalformed,
			"the %s header does not contain expected parts", headerAuthorization,
		)
	}

	signature, err := newSignatureV2FromEncoded(rawSignature)
	if err != nil {
		return v2ParsedAuthorization{}, nestError(
			ErrInvalidSignature,
			"the %s header does not contain a valid signature: %w", headerAuthorization, err,
		)
	}

	return v2ParsedAuthorization{
		accessKeyID: accessKeyID,
		signature:   signature,
	}, nil
}

func (v2 *V2[T]) calculateSignature(r *http.Request, dateElement, bucket, key string) signatureV2 {
	b := newHashBuilder(func() hash.Hash { return hmac.New(sha1.New, []byte(key)) })

	b.WriteString(r.Method)
	b.WriteByte(lf)
	b.WriteString(r.Header.Get(headerContentMD5))
	b.WriteByte(lf)
	b.WriteString(r.Header.Get(headerContentType))
	b.WriteByte(lf)
	b.WriteString(dateElement)
	b.WriteByte(lf)

	var xAmzHeaderPrefixKeys []string
	for key := range r.Header {
		if k := strings.ToLower(key); strings.HasPrefix(k, xAmzHeaderPrefix) {
			xAmzHeaderPrefixKeys = append(xAmzHeaderPrefixKeys, k)
		}
	}
	slices.Sort(xAmzHeaderPrefixKeys)
	for _, key := range xAmzHeaderPrefixKeys {
		b.WriteString(key)
		b.WriteByte(':')
		for i, v := range r.Header.Values(key) {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(v)
		}
		b.WriteByte(lf)
	}

	b.WriteByte('/')
	if bucket != "" {
		escapedPath := r.URL.EscapedPath()
		trimmedEscapedPath := strings.TrimPrefix(escapedPath, "/")

		idx1 := strings.IndexByte(trimmedEscapedPath, '/')
		idx2 := strings.Index(trimmedEscapedPath, "%2F")

		idx := max(idx1, idx2)

		if idx1 >= 0 && idx2 >= 0 {
			idx = min(idx1, idx2)
		}

		b.WriteString(bucket)
		if idx >= 0 && equalUnescaped(trimmedEscapedPath[:idx], bucket) {
			b.WriteString(trimmedEscapedPath[idx:])
		} else {
			b.WriteString(escapedPath)
		}
	}

	if query := r.URL.Query(); len(query) > 0 {
		included := map[string]bool{
			"acl":                          true,
			"lifecycle":                    true,
			"location":                     true,
			"logging":                      true,
			"notification":                 true,
			"partNumber":                   true,
			"policy":                       true,
			"requestPayment":               true,
			"uploadId":                     true,
			"uploads":                      true,
			"versionId":                    true,
			"versioning":                   true,
			"versions":                     true,
			"website":                      true,
			"response-content-type":        false,
			"response-content-language":    false,
			"response-expires":             false,
			"response-cache-control":       false,
			"response-content-disposition": false,
			"response-content-encoding":    false,
			"delete":                       true,
		}

		maps.DeleteFunc(query, func(p string, _ []string) bool {
			_, ok := included[p]
			return !ok
		})
		queryParams := slices.Collect(maps.Keys(query))
		slices.Sort(queryParams)

		for i, p := range queryParams {
			if i == 0 {
				b.WriteByte('?')
			}

			for _, v := range query[p] {
				if i > 0 {
					b.WriteByte('&')
				}
				b.WriteString(p)
				if v != "" {
					b.WriteByte('=')
					if included[p] {
						b.WriteString(uriEncode(v, false))
					} else {
						b.WriteString(v)
					}
				}
			}
		}
	}

	return b.Sum()
}

func (v2 *V2[T]) calculatePostSignature(data, key string) signatureV2 {
	return hmacSHA1([]byte(key), data)
}

func (v2 *V2[T]) verifyPost(ctx context.Context, form PostForm) (v2VerifiedData[T], error) {
	signature, err := newSignatureV2FromEncoded(form.Get(querySignature).Value)
	if err != nil {
		return v2VerifiedData[T]{}, nestError(
			ErrInvalidSignature,
			"the %s form field does not contain a valid signature: %w", querySignature, err,
		)
	}

	policy := form.Get(formNamePolicy).Value
	if policy == "" {
		return v2VerifiedData[T]{}, nestError(
			ErrInvalidRequest,
			"the %s form field is missing", formNamePolicy,
		)
	}

	accessKeyID := form.Get(queryAWSAccessKeyId).Value
	secretAccessKey, data, err := v2.provider.Provide(ctx, accessKeyID)
	if err != nil {
		return v2VerifiedData[T]{}, err
	}

	if !v2.calculatePostSignature(policy, secretAccessKey).compare(signature) {
		return v2VerifiedData[T]{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData[T]{
		authData: data,
	}, nil
}

func (v2 *V2[T]) verify(r *http.Request, bucket string) (v2VerifiedData[T], error) {
	headerDateValue, parsedDateTime, err := v2.parseTime(r.Header)
	if err != nil {
		return v2VerifiedData[T]{}, err
	}

	if parsedDateTime.Unix() < 0 {
		return v2VerifiedData[T]{}, ErrInvalidDateHeader
	}
	if timeSkewExceeded(v2.now, parsedDateTime, maxRequestTimeSkew) {
		return v2VerifiedData[T]{}, ErrRequestTimeTooSkewed
	}

	authorization, err := v2.parseAuthorization(r.Header.Get(headerAuthorization))
	if err != nil {
		return v2VerifiedData[T]{}, err
	}

	secretAccessKey, data, err := v2.provider.Provide(r.Context(), authorization.accessKeyID)
	if err != nil {
		return v2VerifiedData[T]{}, err
	}

	signature := v2.calculateSignature(r, headerDateValue, bucket, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v2VerifiedData[T]{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData[T]{
		authData: data,
	}, nil
}

func (v2 *V2[T]) verifyPresigned(r *http.Request, query url.Values, bucket string) (v2VerifiedData[T], error) {
	rawExpires := query.Get(queryExpires)

	expires, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil {
		return v2VerifiedData[T]{}, ErrInvalidPresignedExpiration
	}

	if v2.now().After(time.Unix(expires, 0)) {
		return v2VerifiedData[T]{}, ErrRequestExpired
	}

	signature, err := newSignatureV2FromEncoded(query.Get(querySignature))
	if err != nil {
		return v2VerifiedData[T]{}, nestError(
			ErrInvalidSignature,
			"the %s query parameter does not contain a valid signature: %w", querySignature, err,
		)
	}

	accessKeyID := query.Get(queryAWSAccessKeyId)
	secretAccessKey, data, err := v2.provider.Provide(r.Context(), accessKeyID)
	if err != nil {
		return v2VerifiedData[T]{}, err
	}

	if !v2.calculateSignature(r, rawExpires, bucket, secretAccessKey).compare(signature) {
		return v2VerifiedData[T]{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData[T]{
		authData: data,
	}, nil
}

// Verify verifies the AWS Signature Version 2 for the given request and
// returns a verified request.
func (v2 *V2[T]) Verify(r *http.Request, bucket string) (*V2VerifiedRequest[T], error) {
	typ, params, err := mime.ParseMediaType(r.Header.Get(headerContentType))
	if err != nil {
		typ = ""
	}

	if r.Method == http.MethodPost && typ == "multipart/form-data" {
		file, form, err := parseMultipartFormUntilFile(r.Body, params["boundary"])
		if err != nil {
			return nil, ErrMalformedPOSTRequest
		}
		data, err := v2.verifyPost(r.Context(), form)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequestWithForm(file, data, form)
	} else if r.Header.Get(headerAuthorization) != "" {
		data, err := v2.verify(r, bucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	} else if query := r.URL.Query(); query.Has(queryAWSAccessKeyId) {
		data, err := v2.verifyPresigned(r, query, bucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	}
	return nil, ErrAccessDenied
}
