package awsig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/zeebo/assert"
)

const data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor"

var dataSha256 = []byte{0x1c, 0x3f, 0x95, 0x8a, 0xbd, 0x85, 0xc5, 0x49, 0x05, 0xc9, 0x7f, 0xe8, 0xe0, 0x62, 0x8f, 0xe7, 0x64, 0x95, 0x71, 0x19, 0x62, 0xa2, 0x7d, 0xaa, 0xe3, 0x40, 0x33, 0x78, 0x14, 0x86, 0xda, 0x00}

func TestIntegrityReader(t *testing.T) {
	ei := make(expectedIntegrity)
	assert.NoError(t, ei.setEncodedString(AlgorithmCRC32, "AMHftQ=="))
	assert.NoError(t, ei.setEncodedString(AlgorithmCRC32C, "L9qeQg=="))
	assert.NoError(t, ei.setEncodedString(AlgorithmCRC64NVME, "sa/Hm4j1eiw="))
	assert.NoError(t, ei.setEncodedString(AlgorithmMD5, "Nes7WPo4rXl6qJFE9UGZww=="))
	assert.NoError(t, ei.setEncodedString(AlgorithmSHA1, "kCwbMV39/ST8gj+3T1hnHpxuz6Y="))
	assert.NoError(t, ei.setEncodedString(AlgorithmSHA256, "HD+Vir2FxUkFyX/o4GKP52SVcRlion2q40AzeBSG2gA="))
	assert.NoError(t, ei.setEncodedString(algorithmHashedPayload, "1c3f958abd85c54905c97fe8e0628fe76495711962a27daae34033781486da00"))

	ir := newIntegrityReader(strings.NewReader(data), []ChecksumAlgorithm{
		AlgorithmCRC32,
		AlgorithmCRC32C,
		AlgorithmCRC64NVME,
		AlgorithmMD5,
		AlgorithmSHA1,
		AlgorithmSHA256,
		algorithmHashedPayload,
	})

	buf := bytes.NewBuffer(nil)

	_, err := io.Copy(buf, ir)
	assert.NoError(t, err)

	assert.Equal(t, data, buf.String())
	assert.NoError(t, ir.verify(ei))

	actual, err := ir.checksums()
	assert.NoError(t, err)
	assert.Equal(t, map[ChecksumAlgorithm][]byte{
		AlgorithmCRC32:     {0x00, 0xc1, 0xdf, 0xb5},
		AlgorithmCRC32C:    {0x2f, 0xda, 0x9e, 0x42},
		AlgorithmCRC64NVME: {0xb1, 0xaf, 0xc7, 0x9b, 0x88, 0xf5, 0x7a, 0x2c},
		AlgorithmMD5:       {0x35, 0xeb, 0x3b, 0x58, 0xfa, 0x38, 0xad, 0x79, 0x7a, 0xa8, 0x91, 0x44, 0xf5, 0x41, 0x99, 0xc3},
		AlgorithmSHA1:      {0x90, 0x2c, 0x1b, 0x31, 0x5d, 0xfd, 0xfd, 0x24, 0xfc, 0x82, 0x3f, 0xb7, 0x4f, 0x58, 0x67, 0x1e, 0x9c, 0x6e, 0xcf, 0xa6},
		AlgorithmSHA256:    dataSha256,
	}, actual)
}

func TestChecksumMismatchError(t *testing.T) {
	ei := expectedIntegrity(map[ChecksumAlgorithm][]byte{
		AlgorithmCRC32:         {0x00, 0xc1, 0xdf, 0xb5},
		AlgorithmSHA256:        []byte("wrong SHA-256 checksum"),
		algorithmHashedPayload: []byte("wrong X-Amz-Content-Sha256 checksum"),
	})

	ir := newIntegrityReader(strings.NewReader(data), []ChecksumAlgorithm{
		AlgorithmCRC32,
		AlgorithmSHA256,
		algorithmHashedPayload,
	})

	_, err := io.Copy(io.Discard, ir)
	assert.NoError(t, err)

	err = ir.verify(ei)
	assert.Error(t, err)

	var mismatchErr ChecksumMismatchError
	assert.True(t, errors.As(err, &mismatchErr))

	slices.SortFunc(mismatchErr.Mismatches, func(a ChecksumMismatch, b ChecksumMismatch) int {
		if algoDiff := int(a.Algorithm - b.Algorithm); algoDiff != 0 {
			return algoDiff
		}
		if a.IsContentSHA256 {
			return 1
		}
		return -1
	})

	assert.Equal(t, []ChecksumMismatch{
		{
			Algorithm:          AlgorithmSHA256,
			ClientChecksum:     ei[AlgorithmSHA256],
			CalculatedChecksum: dataSha256,
			IsContentSHA256:    false,
		},
		{
			Algorithm:          AlgorithmSHA256,
			ClientChecksum:     ei[algorithmHashedPayload],
			CalculatedChecksum: dataSha256,
			IsContentSHA256:    true,
		},
	}, mismatchErr.Mismatches)
}

func TestReaderRetryAfterFailedChecksumRequest(t *testing.T) {
	crc32Req, err := NewChecksumRequest(AlgorithmCRC32, "AAAAAA==")
	assert.NoError(t, err)
	sha1Req, err := NewChecksumRequest(AlgorithmSHA1, "2jmj7l5rSw0yVb/vlWAYkK/YBwk=")
	assert.NoError(t, err)
	otherSHA1Req, err := NewChecksumRequest(AlgorithmSHA1, "qvTGHdzF6KLavt4PO0gs2a6pQ00=")
	assert.NoError(t, err)

	t.Run("V2", func(t *testing.T) {
		vr, err := newV2VerifiedRequest(strings.NewReader(""), v2VerifiedData[struct{}]{})
		assert.NoError(t, err)
		_, err = vr.Reader(sha1Req, otherSHA1Req)
		assert.That(t, errors.Is(err, ErrBadDigest))
		_, err = vr.Reader(sha1Req, crc32Req)
		assert.NoError(t, err)
	})
	t.Run("V4", func(t *testing.T) {
		vr, err := newV4VerifiedRequest(strings.NewReader(""), v4VerifiedData[struct{}]{
			options: parsedXAmzContentSHA256{unsigned: true},
		})
		assert.NoError(t, err)
		_, err = vr.Reader(sha1Req, otherSHA1Req)
		assert.That(t, errors.Is(err, ErrBadDigest))
		rd, err := vr.Reader(sha1Req, crc32Req)
		assert.NoError(t, err)
		_, err = io.ReadAll(rd)
		assert.NoError(t, err)
	})
}

func TestIntegrityReaderSharesSHA256(t *testing.T) {
	one := testing.AllocsPerRun(10, func() { newIntegrityReader(nil, []ChecksumAlgorithm{AlgorithmSHA256}) })
	both := testing.AllocsPerRun(10, func() {
		newIntegrityReader(nil, []ChecksumAlgorithm{algorithmHashedPayload, AlgorithmSHA256})
	})
	assert.Equal(t, one, both)

	ir := newIntegrityReader(strings.NewReader(data), []ChecksumAlgorithm{algorithmHashedPayload, AlgorithmSHA256})
	_, err := io.ReadAll(ir)
	assert.NoError(t, err)
	assert.NoError(t, ir.verify(expectedIntegrity{AlgorithmSHA256: dataSha256, algorithmHashedPayload: dataSha256}))
}

func BenchmarkCRC64NVMEReader(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		r := newIntegrityReader(strings.NewReader(""), []ChecksumAlgorithm{AlgorithmCRC64NVME})
		_, _ = io.Copy(io.Discard, r)
	}
}

func TestChecksumDecodedLengths(t *testing.T) {
	for _, tc := range []struct {
		algorithm ChecksumAlgorithm
		size      int
	}{
		{AlgorithmCRC32, 4}, {AlgorithmCRC32C, 4}, {AlgorithmCRC64NVME, 8},
		{AlgorithmMD5, 16}, {AlgorithmSHA1, 20}, {AlgorithmSHA256, 32},
		{algorithmHashedPayload, 32},
	} {
		for size := tc.size - 2; size <= tc.size+2; size++ {
			t.Run(fmt.Sprintf("%d/%d", tc.algorithm, size), func(t *testing.T) {
				digest := make([]byte, size)
				encoded := base64.StdEncoding.EncodeToString(digest)
				if tc.algorithm == algorithmHashedPayload {
					encoded = hex.EncodeToString(digest)
				}
				_, constructorErr := NewChecksumRequest(tc.algorithm, encoded)
				decoded, decodeErr := decodeChecksum(tc.algorithm, []byte(encoded))
				integrity := make(expectedIntegrity)
				trailerErr := integrity.setEncoded(tc.algorithm, []byte(encoded))
				for name, err := range map[string]error{"constructor": constructorErr, "decoder": decodeErr, "trailer": trailerErr} {
					if size == tc.size && err != nil {
						t.Errorf("%s: %v", name, err)
					}
					if size != tc.size && err == nil {
						t.Errorf("%s accepted %d-byte %s digest", name, size, tc.algorithm)
					}
				}
				if size == tc.size && !bytes.Equal(decoded, digest) {
					t.Fatal("decoded digest differs")
				}
			})
		}
	}
}
