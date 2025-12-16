package awsig

import (
	"bytes"
	"errors"
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
