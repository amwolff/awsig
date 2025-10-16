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

type v2VerifiedData struct {
	accessKeyID string
}

// V2VerifiedRequest implements VerifiedRequest for AWS Signature
// Version 2.
type V2VerifiedRequest struct {
	form   PostForm
	data   v2VerifiedData
	source io.Reader

	wrapped *v2Reader

	algorithms []ChecksumAlgorithm
	integrity  expectedIntegrity
}

func newV2VerifiedRequestWithForm(source io.Reader, data v2VerifiedData, form PostForm) (*V2VerifiedRequest, error) {
	return &V2VerifiedRequest{
		form:      form,
		data:      data,
		source:    source,
		integrity: make(expectedIntegrity),
	}, nil
}

func newV2VerifiedRequest(source io.Reader, data v2VerifiedData) (*V2VerifiedRequest, error) {
	return newV2VerifiedRequestWithForm(source, data, nil)
}

// AccessKeyID implements VerifiedRequest.
func (vr *V2VerifiedRequest) AccessKeyID() string {
	return vr.data.accessKeyID
}

// PostForm implements VerifiedRequest.
func (vr *V2VerifiedRequest) PostForm() PostForm {
	return vr.form
}

func (vr *V2VerifiedRequest) addAlgorithm(algorithm ChecksumAlgorithm) error {
	if slices.Contains(vr.algorithms, algorithm) {
		return errors.New("algorithm already added")
	}
	vr.algorithms = append(vr.algorithms, algorithm)
	return nil
}

func (vr *V2VerifiedRequest) requestChecksum(req ChecksumRequest) error {
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

func (vr *V2VerifiedRequest) requestChecksums(reqs []ChecksumRequest) error {
	for i, req := range reqs {
		if err := vr.requestChecksum(req); err != nil {
			return fmt.Errorf("could not process request %d: %w", i, err)
		}
	}
	return nil
}

// Reader implements VerifiedRequest.
func (vr *V2VerifiedRequest) Reader(reqs ...ChecksumRequest) (Reader, error) {
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
type V2 struct {
	provider CredentialsProvider
	now      func() time.Time
}

// NewV2 creates a new V2 with the given provider.
func NewV2(provider CredentialsProvider) *V2 {
	return &V2{
		provider: provider,
		now:      time.Now,
	}
}

func (v2 *V2) parseTime(main, alt string) (time.Time, error) {
	parsed, err := parseTimeWithFormats(main, httpTimeFormats)
	if err != nil {
		return parseTimeWithFormats(alt, httpTimeFormats)
	}
	return parsed, nil
}

type v2ParsedAuthorization struct {
	accessKeyID string
	signature   signatureV2
}

func (v2 *V2) parseAuthorization(rawAuthorization string) (v2ParsedAuthorization, error) {
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

func (v2 *V2) calculateSignature(r *http.Request, dateElement, virtualHostedBucket, key string) signatureV2 {
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

	if virtualHostedBucket != "" {
		b.WriteByte('/')
		b.WriteString(virtualHostedBucket)
	}
	// NOTE(amwolff): it felt like a bad idea to use a RawPath that
	// might contain an invalid encoding the software down the chain
	// might use long after we've authenticated this request.
	b.WriteString(r.URL.EscapedPath())

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

		queryParams := slices.Collect(maps.Keys(query))
		slices.Sort(queryParams)

		for i, p := range queryParams {
			encode, ok := included[p]
			if !ok {
				continue
			}

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
					if encode {
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

func (v2 *V2) calculatePostSignature(data, key string) signatureV2 {
	return hmacSHA1([]byte(key), data)
}

func (v2 *V2) verifyPost(ctx context.Context, form PostForm) (v2VerifiedData, error) {
	rawSignature, _ := form.Get(querySignature)
	signature, err := newSignatureV2FromEncoded(rawSignature)
	if err != nil {
		return v2VerifiedData{}, nestError(
			ErrInvalidSignature,
			"the %s form field does not contain a valid signature: %w", querySignature, err,
		)
	}

	policy, _ := form.Get(formNamePolicy)
	if policy == "" {
		return v2VerifiedData{}, nestError(
			ErrInvalidRequest,
			"the %s form field is missing", formNamePolicy,
		)
	}

	accessKeyID, _ := form.Get(queryAWSAccessKeyId)
	secretAccessKey, err := v2.provider.Provide(ctx, accessKeyID)
	if err != nil {
		return v2VerifiedData{}, err
	}

	if !v2.calculatePostSignature(policy, secretAccessKey).compare(signature) {
		return v2VerifiedData{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData{
		accessKeyID: accessKeyID,
	}, nil
}

func (v2 *V2) verify(r *http.Request, virtualHostedBucket string) (v2VerifiedData, error) {
	headerDateValue := r.Header.Get(headerDate)
	parsedDateTime, err := v2.parseTime(r.Header.Get(headerXAmzDate), headerDateValue)
	if err != nil {
		return v2VerifiedData{}, nestError(
			ErrInvalidRequest,
			"the %s or %s header does not contain a valid date: %w", headerXAmzDate, headerDate, err,
		)
	}

	if timeSkewExceeded(v2.now, parsedDateTime, maxRequestTimeSkew) {
		return v2VerifiedData{}, ErrRequestTimeTooSkewed
	}

	authorization, err := v2.parseAuthorization(r.Header.Get(headerAuthorization))
	if err != nil {
		return v2VerifiedData{}, err
	}

	secretAccessKey, err := v2.provider.Provide(r.Context(), authorization.accessKeyID)
	if err != nil {
		return v2VerifiedData{}, err
	}

	signature := v2.calculateSignature(r, headerDateValue, virtualHostedBucket, secretAccessKey)

	if !signature.compare(authorization.signature) {
		return v2VerifiedData{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData{
		accessKeyID: authorization.accessKeyID,
	}, nil
}

func (v2 *V2) verifyPresigned(r *http.Request, query url.Values, virtualHostedBucket string) (v2VerifiedData, error) {
	rawExpires := query.Get(queryExpires)

	expires, err := strconv.ParseInt(rawExpires, 10, 64)
	if err != nil {
		return v2VerifiedData{}, nestError(
			ErrInvalidRequest,
			"the %s query parameter does not contain a valid integer: %w", queryExpires, err,
		)
	}

	if timeOutOfBounds(v2.now, time.Time{}, time.Unix(expires, 0)) {
		return v2VerifiedData{}, ErrAccessDenied
	}

	signature, err := newSignatureV2FromEncoded(query.Get(querySignature))
	if err != nil {
		return v2VerifiedData{}, nestError(
			ErrInvalidSignature,
			"the %s query parameter does not contain a valid signature: %w", querySignature, err,
		)
	}

	accessKeyID := query.Get(queryAWSAccessKeyId)
	secretAccessKey, err := v2.provider.Provide(r.Context(), accessKeyID)
	if err != nil {
		return v2VerifiedData{}, err
	}

	if !v2.calculateSignature(r, rawExpires, virtualHostedBucket, secretAccessKey).compare(signature) {
		return v2VerifiedData{}, ErrSignatureDoesNotMatch
	}

	return v2VerifiedData{
		accessKeyID: accessKeyID,
	}, nil
}

// Verify verifies the AWS Signature Version 2 for the given request and
// returns a verified request.
func (v2 *V2) Verify(r *http.Request, virtualHostedBucket string) (*V2VerifiedRequest, error) {
	typ, params, err := mime.ParseMediaType(r.Header.Get(headerContentType))
	if err != nil {
		typ = ""
	}

	if r.Method == http.MethodPost && typ == "multipart/form-data" {
		file, form, err := parseMultipartFormUntilFile(r.Body, params["boundary"])
		if err != nil {
			return nil, nestError(
				ErrInvalidRequest,
				"unable to parse multipart form data: %w", err,
			)
		}
		data, err := v2.verifyPost(r.Context(), form)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequestWithForm(file, data, form)
	} else if r.Header.Get(headerAuthorization) != "" {
		data, err := v2.verify(r, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	} else if query := r.URL.Query(); query.Has(queryAWSAccessKeyId) {
		data, err := v2.verifyPresigned(r, query, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	}
	return nil, ErrMissingAuthenticationToken
}
