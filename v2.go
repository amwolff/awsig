package awsig

import (
	"bytes"
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

// v2SignedSubresources matches HmacV1Auth.QSAOfInterest in botocore 1.40.0:
// https://github.com/boto/botocore/blob/1.40.0/botocore/auth.py#L795-L834
// Keep one canonicalization policy; do not retry signatures with other SDK lists.
// Known operation selectors outside this list are rejected by validateV2Query.
var v2SignedSubresources = map[string]struct{}{
	"accelerate":                   {},
	"acl":                          {},
	"analytics":                    {},
	"cors":                         {},
	"defaultObjectAcl":             {},
	"delete":                       {},
	"inventory":                    {},
	"lifecycle":                    {},
	"location":                     {},
	"logging":                      {},
	"metrics":                      {},
	"notification":                 {},
	"object-lock":                  {},
	"partNumber":                   {},
	"policy":                       {},
	"replication":                  {},
	"requestPayment":               {},
	"restore":                      {},
	"select":                       {},
	"select-type":                  {},
	"storageClass":                 {},
	"tagging":                      {},
	"torrent":                      {},
	"uploadId":                     {},
	"uploads":                      {},
	"versionId":                    {},
	"versioning":                   {},
	"versions":                     {},
	"website":                      {},
	"response-content-type":        {},
	"response-content-language":    {},
	"response-expires":             {},
	"response-cache-control":       {},
	"response-content-disposition": {},
	"response-content-encoding":    {},
}

// validateV2Query prevents known operation selectors omitted by the pinned
// signer from being accepted as unsigned parameters. Use SigV4 for these APIs.
func validateV2Query(query url.Values) error {
	for _, key := range []string{"encryption", "legal-hold", "retention", "intelligent-tiering", "ownershipControls", "policyStatus", "publicAccessBlock"} {
		if query.Has(key) {
			return nestError(ErrInvalidRequest, "the %s operation requires SigV4", key)
		}
	}
	return nil
}

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

// PostForm implements [VerifiedRequest.PostForm].
func (vr *V2VerifiedRequest[T]) PostForm() PostForm {
	return vr.form
}

func (vr *V2VerifiedRequest[T]) requestChecksum(req ChecksumRequest) error {
	if !req.valid() {
		return fmt.Errorf("uninitialized request")
	}
	if req.trailing {
		return nestError(ErrInvalidChecksumRequest, "could not add %s: trailing checksums are not supported in V2", req.algorithm)
	}
	if expected, ok := vr.integrity[req.algorithm]; ok {
		// Content-MD5 and X-Amz-Checksum-Md5 may both carry the same digest.
		if !bytes.Equal(expected, req.value) {
			return nestError(ErrBadDigest, "conflicting %s checksums were provided", req.algorithm)
		}
		return nil
	}
	vr.algorithms = append(vr.algorithms, req.algorithm)
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

	algorithms, integrity := vr.algorithms, maps.Clone(vr.integrity)
	if err := vr.requestChecksums(reqs); err != nil {
		vr.algorithms, vr.integrity = algorithms, integrity
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
		return "", parsed, nil
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

func (v2 *V2[T]) calculateSignature(r *http.Request, query url.Values, dateElement, virtualHostedBucket, key string) signatureV2 {
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
			// net/http unfolds HTTP headers; trim each value before joining.
			b.WriteString(strings.TrimSpace(v))
		}
		b.WriteByte(lf)
	}

	if virtualHostedBucket != "" {
		b.WriteByte('/')
		b.WriteString(virtualHostedBucket)
	}
	// NOTE(amwolff): it felt like a bad idea to use a RawPath that
	// might contain an invalid encoding the software down the chain
	// might use long after we've authenticated this request.
	b.WriteString(r.URL.EscapedPath())
	if virtualHostedBucket == "" {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" && !strings.Contains(path, "/") {
			// Preserve compatibility with clients that send /bucket but sign
			// /bucket/. Only path-style bucket-only requests get this suffix;
			// object paths and virtual-hosted requests must remain unchanged.
			b.WriteByte('/')
		}
	}

	if len(query) > 0 {
		queryParams := make([]string, 0, len(query))
		for p := range query {
			if _, ok := v2SignedSubresources[p]; ok {
				queryParams = append(queryParams, p)
			}
		}
		slices.Sort(queryParams)

		first := true
		for _, p := range queryParams {
			for _, v := range query[p] {
				if first {
					b.WriteByte('?')
				} else {
					b.WriteByte('&')
				}
				first = false
				b.WriteString(p)
				if v != "" {
					b.WriteByte('=')
					// SigV2 signers use decoded subresource and response-header values.
					b.WriteString(v)
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
		return v2VerifiedData[T]{}, ErrMissingPOSTPolicy
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

func (v2 *V2[T]) verify(r *http.Request, query url.Values, virtualHostedBucket string) (v2VerifiedData[T], error) {
	if err := validateV2Query(query); err != nil {
		return v2VerifiedData[T]{}, err
	}
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

	signature := v2.calculateSignature(r, query, headerDateValue, virtualHostedBucket, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v2VerifiedData[T]{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData[T]{
		authData: data,
	}, nil
}

func (v2 *V2[T]) verifyPresigned(r *http.Request, query url.Values, virtualHostedBucket string) (v2VerifiedData[T], error) {
	if err := validateV2Query(query); err != nil {
		return v2VerifiedData[T]{}, err
	}
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

	if !v2.calculateSignature(r, query, rawExpires, virtualHostedBucket, secretAccessKey).compare(signature) {
		return v2VerifiedData[T]{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData[T]{
		authData: data,
	}, nil
}

// Verify verifies the AWS Signature Version 2 for the given request and
// returns a verified request.
//
// See [VerifiedRequest.PostForm] for multipart POST policy validation requirements.
func (v2 *V2[T]) Verify(r *http.Request, virtualHostedBucket string) (*V2VerifiedRequest[T], error) {
	query, err := parseRequestQuery(r)
	if err != nil {
		return nil, err
	}

	typ, params, err := mime.ParseMediaType(r.Header.Get(headerContentType))
	if err != nil {
		typ = ""
	}

	switch {
	case r.Method == http.MethodPost && typ == "multipart/form-data":
		if err := validateV2Query(query); err != nil {
			return nil, err
		}
		file, form, err := parseMultipartFormUntilFile(r.Body, params["boundary"])
		if err != nil {
			return nil, nestError(ErrMalformedPOSTRequest, "parse multipart form: %w", err)
		}
		data, err := v2.verifyPost(r.Context(), form)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequestWithForm(file, data, form)
	case r.Header.Get(headerAuthorization) != "":
		data, err := v2.verify(r, query, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	case query.Has(queryAWSAccessKeyId):
		data, err := v2.verifyPresigned(r, query, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	}
	return nil, ErrAccessDenied
}
