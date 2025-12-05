package awsig

import (
	"mime"
	"net/http"
	"strings"
)

// V2V4 implements AWS Signature Version 2 and AWS Signature Version 4
// verification.
type V2V4[T any] struct {
	v2 *V2[T]
	v4 *V4[T]
}

// NewV2V4 creates a new V2V4 with the given provider and v4Config.
func NewV2V4[T any](provider CredentialsProvider[T], v4Config V4Config) *V2V4[T] {
	return &V2V4[T]{
		v2: NewV2(provider),
		v4: NewV4(provider, v4Config),
	}
}

// Verify automatically detects and verifies either AWS Signature
// Version 2 or AWS Signature Version 4 for the given request and
// returns a verified request.
func (v2v4 *V2V4[T]) Verify(r *http.Request, virtualHostedBucket string) (VerifiedRequest[T], error) {
	typ, params, err := mime.ParseMediaType(r.Header.Get(headerContentType))
	if err != nil {
		typ = ""
	}

	if r.Method == http.MethodPost && typ == "multipart/form-data" {
		file, form, err := parseMultipartFormUntilFile(r.Body, params["boundary"])
		if err != nil {
			return nil, ErrMalformedPOSTRequest
		}
		if form.Has(queryXAmzAlgorithm) {
			data, err := v2v4.v4.verifyPost(r.Context(), form)
			if err != nil {
				return nil, err
			}
			return newV4VerifiedRequestWithForm(file, data, form)
		} else if form.Has(queryAWSAccessKeyId) {
			data, err := v2v4.v2.verifyPost(r.Context(), form)
			if err != nil {
				return nil, err
			}
			return newV2VerifiedRequestWithForm(file, data, form)
		}
	} else if h := r.Header.Get(headerAuthorization); h != "" {
		if strings.HasPrefix(h, v4SigningAlgorithmPrefix) {
			data, err := v2v4.v4.verify(r)
			if err != nil {
				return nil, err
			}
			return newV4VerifiedRequest(r.Body, data)
		}
		data, err := v2v4.v2.verify(r, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	} else if query := r.URL.Query(); query.Has(queryXAmzAlgorithm) {
		data, err := v2v4.v4.verifyPresigned(r, query)
		if err != nil {
			return nil, err
		}
		return newV4VerifiedRequest(r.Body, data)
	} else if query.Has(queryAWSAccessKeyId) {
		data, err := v2v4.v2.verifyPresigned(r, query, virtualHostedBucket)
		if err != nil {
			return nil, err
		}
		return newV2VerifiedRequest(r.Body, data)
	}

	return nil, ErrMissingAuthenticationToken
}
