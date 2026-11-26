package awsig

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"

	"github.com/zeebo/assert"
)

func TestV4ReaderMetadataFitsTrailers(t *testing.T) {
	var r v4Reader
	for algo := AlgorithmCRC32; algo < algorithmHashedPayload; algo++ {
		for _, unsigned := range []bool{false, true} {
			_, trailer := chunkTrailerMaxLengths(algo, unsigned)
			assert.That(t, trailer <= len(r.metadata))
		}
	}
}

func TestV4ReaderReadAll(t *testing.T) {
	// io.ReadAll starts with a 512-byte buffer and passes Read what is left of it. After 476 bytes
	// of data that is 36 bytes, one fewer than this trailer can take.
	data := strings.Repeat("a", 476)
	sum := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE([]byte(data))))
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n", len(data), data, sum)

	opts := parsedXAmzContentSHA256{unsigned: true, streaming: true, trailer: true, decodedContentLength: int64(len(data))}
	vr, err := newV4VerifiedRequest(strings.NewReader(body), v4VerifiedData[struct{}]{options: opts})
	assert.NoError(t, err)
	req, err := NewTrailingChecksumRequest(AlgorithmCRC32)
	assert.NoError(t, err)
	r, err := vr.Reader(req)
	assert.NoError(t, err)

	got, err := io.ReadAll(r)
	assert.NoError(t, err)
	assert.Equal(t, data, string(got))
}

func TestV4ReaderSmallBuffers(t *testing.T) {
	ir := newIntegrityReader(strings.NewReader("hello"), []ChecksumAlgorithm{AlgorithmSHA256})
	_, err := io.ReadAll(ir)
	assert.NoError(t, err)
	assert.NoError(t, ir.verify(nil))
	sums, err := ir.checksums()
	assert.NoError(t, err)
	body := "5\r\nhello\r\n0\r\nx-amz-checksum-sha256:" + base64.StdEncoding.EncodeToString(sums[AlgorithmSHA256]) + "\r\n\r\n"

	for _, size := range []int{1, 2, 7, 64} {
		opts := parsedXAmzContentSHA256{unsigned: true, streaming: true, trailer: true, decodedContentLength: 5}
		vr, err := newV4VerifiedRequest(strings.NewReader(body), v4VerifiedData[struct{}]{options: opts})
		assert.NoError(t, err)
		req, err := NewTrailingChecksumRequest(AlgorithmSHA256)
		assert.NoError(t, err)
		r, err := vr.Reader(req)
		assert.NoError(t, err)

		var got []byte
		for {
			p := make([]byte, size) // a fresh buffer, so its capacity is size too
			n, err := r.Read(p)
			got = append(got, p[:n]...)
			if errors.Is(err, io.EOF) {
				break
			}
			assert.NoError(t, err)
		}
		assert.Equal(t, "hello", string(got))
	}
}
