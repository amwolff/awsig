package awsig

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/url"
)

const (
	signatureV2DecodedLength = 20
	signatureV2EncodedLength = 28
)

type signatureV2 []byte

func newSignatureV2FromEncoded(s string) (signatureV2, error) {
	if len(s) != signatureV2EncodedLength {
		return nil, errors.New("invalid signature length")
	}

	return base64.StdEncoding.DecodeString(s)
}

func (s signatureV2) compare(other signatureV2) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV2) String() string {
	return base64.StdEncoding.EncodeToString(s)
}

func hmacSHA1(key []byte, s string) []byte {
	h := hmac.New(sha1.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func calculateSignatureV2(stringToSign string, secretAccessKey string) signatureV2 {
	return hmacSHA1([]byte(secretAccessKey), stringToSign)
}

func equalUnescaped(escaped, unescaped string) bool {
	unescaped2, err := url.PathUnescape(escaped)
	return err == nil && unescaped2 == unescaped
}
