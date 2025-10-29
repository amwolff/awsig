package awsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"hash"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	v4SigningAlgorithmPrefix = "AWS4-"

	signatureV4DecodedLength = 32
	signatureV4EncodedLength = 64
)

type v4SigningAlgorithm int

const (
	algorithmHMACSHA256 v4SigningAlgorithm = iota
	algorithmECDSAP256SHA256
)

func (a v4SigningAlgorithm) String() string {
	switch a {
	case algorithmHMACSHA256:
		return "HMAC-SHA256"
	case algorithmECDSAP256SHA256:
		return "ECDSA-P256-SHA256"
	default:
		return ""
	}
}

type v4SigningAlgorithmSuffix int

const (
	algorithmSuffixNone v4SigningAlgorithmSuffix = iota
	algorithmSuffixPayload
	algorithmSuffixTrailer
)

func (s v4SigningAlgorithmSuffix) String() string {
	switch s {
	case algorithmSuffixPayload:
		return "-PAYLOAD"
	case algorithmSuffixTrailer:
		return "-TRAILER"
	default:
		return ""
	}
}

type scope struct {
	date    string
	region  string
	service string
}

func (s scope) String() string {
	return s.date + "/" + s.region + "/" + s.service + "/" + v4AuthorizationHeaderCredentialTerminator
}

type signatureV4 []byte

func newSignatureV4FromEncoded(b []byte) (signatureV4, error) {
	if len(b) != signatureV4EncodedLength {
		return nil, ErrInvalidSignature
	}

	s := make(signatureV4, signatureV4DecodedLength)

	n, err := hex.Decode(s, b)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	if n != signatureV4DecodedLength {
		return nil, ErrInvalidSignature
	}

	return s, nil
}

func (s signatureV4) compare(other signatureV4) bool {
	return subtle.ConstantTimeCompare(s, other) == 1
}

func (s signatureV4) String() string {
	return hex.EncodeToString(s)
}

type signatureV4Data struct {
	algorithm       v4SigningAlgorithm
	algorithmSuffix v4SigningAlgorithmSuffix
	dateTime        string
	scope           scope
	previous        signatureV4
	digest          []byte
}

func hmacSHA256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

func signingKeyHMACSHA256(key, date, region, service string) []byte {
	dateKey := hmacSHA256([]byte("AWS4"+key), date)
	dateRegionKey := hmacSHA256(dateKey, region)
	dateRegionServiceKey := hmacSHA256(dateRegionKey, service)
	return hmacSHA256(dateRegionServiceKey, v4AuthorizationHeaderCredentialTerminator)
}

func calculateSignatureV4(data signatureV4Data, secretAccessKey string) signatureV4 {
	if data.algorithm == algorithmECDSAP256SHA256 {
		panic("not implemented")
	}

	key := signingKeyHMACSHA256(secretAccessKey, data.scope.date, data.scope.region, data.scope.service)

	b := newHashBuilder(func() hash.Hash { return hmac.New(sha256.New, key) })

	b.WriteString(v4SigningAlgorithmPrefix)
	b.WriteString(data.algorithm.String())
	b.WriteString(data.algorithmSuffix.String())
	b.WriteByte(lf)
	b.WriteString(data.dateTime)
	b.WriteByte(lf)
	b.WriteString(data.scope.String())
	b.WriteByte(lf)

	switch data.algorithmSuffix {
	case algorithmSuffixPayload:
		b.WriteString(data.previous.String())
		b.WriteByte(lf)
		b.WriteString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		b.WriteByte(lf)
	case algorithmSuffixTrailer:
		b.WriteString(data.previous.String())
		b.WriteByte(lf)
	}

	hex.NewEncoder(b).Write(data.digest) //nolint:errcheck

	return b.Sum()
}

func reuseBuffer(buf []byte, size int) ([]byte, error) {
	if cap(buf) < size {
		return nil, io.ErrShortBuffer
	}
	return buf[:size], nil
}

func sha256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func trimSpaceLeft(s string) string {
	// Fast path for ASCII: look for the first ASCII non-space byte
	start := 0
	for ; start < len(s); start++ {
		c := s[start]
		if c >= utf8.RuneSelf {
			// If we run into a non-ASCII byte, fall back to the slower
			// unicode-aware method on the remaining bytes
			return strings.TrimLeftFunc(s[start:], unicode.IsSpace)
		}
		if asciiSpace[c] == 0 {
			break
		}
	}

	// At this point s[start:] starts with an ASCII non-space bytes, so
	// we're done. Non-ASCII cases have already been handled above.
	return s[start:]
}
