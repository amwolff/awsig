package awsig

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/zeebo/assert"
)

func TestSignatureV4(t *testing.T) {
	t.Run("invalid length", func(t *testing.T) {
		_, err := newSignatureV4FromEncoded([]byte("ąćęłńóśźż"))
		assert.Error(t, err)
	})
	t.Run("invalid bytes", func(t *testing.T) {
		_, err := newSignatureV4FromEncoded(bytes.Repeat([]byte{0}, signatureV4EncodedLength))
		assert.Error(t, err)
	})

	const encoded = "8a3b178891dc9e6305f3231d7340cfc7bc43f18d2b58be1c764786980005a741"

	signature := mustNewSignatureV4FromEncoded(encoded)
	otherSame := mustNewSignatureV4FromEncoded(encoded)
	otherDiff := mustNewSignatureV4FromEncoded("2d8c2f6d978ca21712b5f6de36c9d31fa8e96a4fa5d8ff8b0188dfb9e7c171bb")

	assert.True(t, signature.compare(otherSame))
	assert.Equal(t, encoded, signature.String())
	assert.Equal(t, encoded, otherSame.String())
	assert.False(t, signature.compare(otherDiff))
}

func TestCalculateSignatureV4(t *testing.T) {
	const (
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		dateTime        = "20130524T000000Z"
	)

	scope := scope{
		date:    "20130524",
		region:  "us-east-1",
		service: "s3",
	}

	t.Run("no suffix", func(t *testing.T) {
		digest := mustHexDecodeString("9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d")
		data := signatureV4Data{
			algorithm:       algorithmHMACSHA256,
			algorithmSuffix: algorithmSuffixNone,
			dateTime:        dateTime,
			scope:           scope,
			previous:        nil,
			digest:          digest,
		}

		actual := calculateSignatureV4(data, secretAccessKey)
		expected := mustNewSignatureV4FromEncoded("98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd")

		assert.True(t, expected.compare(actual))
	})
	t.Run("with AWS4-HMAC-SHA256-PAYLOAD", func(t *testing.T) {
		previous := mustNewSignatureV4FromEncoded("4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
		digest := mustHexDecodeString("bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a")
		data := signatureV4Data{
			algorithm:       algorithmHMACSHA256,
			algorithmSuffix: algorithmSuffixPayload,
			dateTime:        dateTime,
			scope:           scope,
			previous:        previous,
			digest:          digest,
		}

		actual := calculateSignatureV4(data, secretAccessKey)
		expected := mustNewSignatureV4FromEncoded("ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648")

		assert.True(t, expected.compare(actual))
	})
	t.Run("with AWS4-HMAC-SHA256-TRAILER", func(t *testing.T) {
		previous := mustNewSignatureV4FromEncoded("2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992")
		digest := mustHexDecodeString("1e376db7e1a34a8ef1c4bcee131a2d60a1cb62503747488624e10995f448d774")
		data := signatureV4Data{
			algorithm:       algorithmHMACSHA256,
			algorithmSuffix: algorithmSuffixTrailer,
			dateTime:        dateTime,
			scope:           scope,
			previous:        previous,
			digest:          digest,
		}

		actual := calculateSignatureV4(data, secretAccessKey)
		expected := mustNewSignatureV4FromEncoded("d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435")

		assert.True(t, expected.compare(actual))
	})
}

func TestReuseBuffer(t *testing.T) {
	buf := make([]byte, 2)
	{
		b, err := reuseBuffer(buf, 1)
		assert.NoError(t, err)
		assert.Equal(t, 1, len(b))
	}
	{
		b, err := reuseBuffer(buf, 2)
		assert.NoError(t, err)
		assert.Equal(t, buf, b)
	}
	{
		_, err := reuseBuffer(buf, 3)
		assert.Error(t, err)
	}
}

func TestSHA256Hash(t *testing.T) {
	const (
		hashZero = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		hashTest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	)

	assert.Equal(t, hashZero, hex.EncodeToString(sha256Hash(nil)))
	assert.Equal(t, hashTest, hex.EncodeToString(sha256Hash([]byte("test"))))
}

func TestTrimSpaceLeft(t *testing.T) {
	assert.Equal(t, "", trimSpaceLeft(""))
	assert.Equal(t, "", trimSpaceLeft("     "))
	assert.Equal(t, "text", trimSpaceLeft("text"))
	assert.Equal(t, "text", trimSpaceLeft("   text"))
	assert.Equal(t, "text  ", trimSpaceLeft("   text  "))
}

func mustNewSignatureV4FromEncoded(s string) signatureV4 {
	signature, err := newSignatureV4FromEncoded([]byte(s))
	if err != nil {
		panic(err)
	}
	return signature
}

func mustHexDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
