package awsig

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"slices"
	"strconv"
)

// ChecksumAlgorithm represents different checksum algorithms supported
// by this package.
type ChecksumAlgorithm int

const (
	// AlgorithmCRC32 represents the CRC-32 checksum algorithm.
	AlgorithmCRC32 ChecksumAlgorithm = iota
	// AlgorithmCRC32C represents the CRC-32C checksum algorithm.
	AlgorithmCRC32C
	// AlgorithmCRC64NVME represents the CRC-64/NVME checksum algorithm.
	AlgorithmCRC64NVME
	// AlgorithmMD5 represents the MD5 checksum algorithm.
	AlgorithmMD5
	// AlgorithmSHA1 represents the SHA-1 checksum algorithm.
	AlgorithmSHA1
	// AlgorithmSHA256 represents the SHA-256 checksum algorithm.
	AlgorithmSHA256
	algorithmHashedPayload
)

func (a ChecksumAlgorithm) base64Length() int {
	switch a {
	case AlgorithmCRC32, AlgorithmCRC32C:
		return base64.StdEncoding.EncodedLen(crc32.Size)
	case AlgorithmCRC64NVME:
		return base64.StdEncoding.EncodedLen(crc64.Size)
	case AlgorithmMD5:
		return base64.StdEncoding.EncodedLen(md5.Size)
	case AlgorithmSHA1:
		return base64.StdEncoding.EncodedLen(sha1.Size)
	case AlgorithmSHA256, algorithmHashedPayload:
		return base64.StdEncoding.EncodedLen(sha256.Size)
	default:
		return 0
	}
}

func (a ChecksumAlgorithm) valid() bool {
	return a >= AlgorithmCRC32 && a <= algorithmHashedPayload
}

func (a ChecksumAlgorithm) String() string {
	switch a {
	case AlgorithmCRC32:
		return "crc32"
	case AlgorithmCRC32C:
		return "crc32c"
	case AlgorithmCRC64NVME:
		return "crc64nvme"
	case AlgorithmMD5:
		return "md5"
	case AlgorithmSHA1:
		return "sha1"
	case AlgorithmSHA256, algorithmHashedPayload:
		return "sha256"
	default:
		return strconv.Itoa(int(a))
	}
}

// ChecksumRequest represents a request to compute or verify a specific
// checksum.
type ChecksumRequest struct {
	value     []byte
	trailing  bool
	algorithm ChecksumAlgorithm
}

func (r ChecksumRequest) valid() bool {
	return r.value != nil || r.trailing
}

// NewChecksumRequest creates a new ChecksumRequest with the specified
// algorithm and encoded value.
func NewChecksumRequest(algorithm ChecksumAlgorithm, encodedValue string) (ChecksumRequest, error) {
	if !algorithm.valid() {
		return ChecksumRequest{}, errors.New("invalid algorithm")
	}
	v, err := decodeChecksumString(algorithm, encodedValue)
	if err != nil {
		return ChecksumRequest{}, err
	}
	return ChecksumRequest{
		value:     v,
		algorithm: algorithm,
	}, nil
}

// NewTrailingChecksumRequest creates a new ChecksumRequest for trailing
// checksum verification.
func NewTrailingChecksumRequest(algorithm ChecksumAlgorithm) (ChecksumRequest, error) {
	if !algorithm.valid() {
		return ChecksumRequest{}, errors.New("invalid algorithm")
	}
	switch algorithm {
	case algorithmHashedPayload:
		return ChecksumRequest{}, errors.New("unsupported algorithm")
	default:
		return ChecksumRequest{
			trailing:  true,
			algorithm: algorithm,
		}, nil
	}
}

type expectedIntegrity map[ChecksumAlgorithm][]byte

func (i expectedIntegrity) setDecoded(a ChecksumAlgorithm, value []byte) {
	i[a] = value
}

func (i expectedIntegrity) setEncoded(a ChecksumAlgorithm, value []byte) error {
	v, err := decodeChecksum(a, value)
	if err != nil {
		return err
	}
	i.setDecoded(a, v)
	return nil
}

func (i expectedIntegrity) setEncodedString(a ChecksumAlgorithm, value string) error {
	v, err := decodeChecksumString(a, value)
	if err != nil {
		return err
	}
	i.setDecoded(a, v)
	return nil
}

type integrityReader struct {
	r io.Reader

	hashes map[ChecksumAlgorithm]hash.Hash
	sums   map[ChecksumAlgorithm][]byte
}

func (r *integrityReader) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}

func (r *integrityReader) checksums() (map[ChecksumAlgorithm][]byte, error) {
	if r.sums == nil {
		return nil, errors.New("verify has not been called yet")
	}

	sums := make(map[ChecksumAlgorithm][]byte, len(r.sums))

	for k, v := range r.sums {
		sums[k] = slices.Clone(v)
	}

	return sums, nil
}

func (r *integrityReader) verify(integrity expectedIntegrity) error {
	r.sums = make(map[ChecksumAlgorithm][]byte)

	var errs error
	for algo := range integrity {
		if _, ok := r.hashes[algo]; !ok {
			errs = errors.Join(errs, fmt.Errorf("calculation of %s was not requested", algo))
		}
	}
	for algo, h := range r.hashes {
		sum := h.Sum(nil)

		if algo != algorithmHashedPayload {
			r.sums[algo] = sum
		}

		if expected, ok := integrity[algo]; ok && !bytes.Equal(expected, sum) {
			errs = errors.Join(errs, fmt.Errorf("%s do not match: expected %x, got %x", algo, expected, sum))
		}
	}

	return errs
}

func newIntegrityReader(r io.Reader, algorithms []ChecksumAlgorithm) *integrityReader {
	ir := &integrityReader{
		hashes: make(map[ChecksumAlgorithm]hash.Hash),
	}

	var writers []io.Writer

	h := md5.New()
	ir.hashes[AlgorithmMD5] = h // MD5 is always computed
	writers = append(writers, h)

	for _, a := range algorithms {
		switch a {
		case AlgorithmCRC32:
			h = crc32.NewIEEE()
			ir.hashes[AlgorithmCRC32] = h
			writers = append(writers, h)
		case AlgorithmCRC32C:
			h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
			ir.hashes[AlgorithmCRC32C] = h
			writers = append(writers, h)
		case AlgorithmCRC64NVME:
			h = crc64.New(crc64.MakeTable(0x9a6c_9329_ac4b_c9b5))
			ir.hashes[AlgorithmCRC64NVME] = h
			writers = append(writers, h)
		case AlgorithmSHA1:
			h = sha1.New()
			ir.hashes[AlgorithmSHA1] = h
			writers = append(writers, h)
		case AlgorithmSHA256, algorithmHashedPayload:
			h = sha256.New()
			ir.hashes[AlgorithmSHA256] = h
			ir.hashes[algorithmHashedPayload] = h
			writers = append(writers, h)
		}
	}

	ir.r = io.TeeReader(r, io.MultiWriter(writers...))

	return ir
}

func testChecksumLen(a ChecksumAlgorithm, v []byte) error {
	var want, got int

	switch a {
	case algorithmHashedPayload:
		want, got = hex.EncodedLen(sha256.Size), len(v)
	default:
		want, got = a.base64Length(), len(v)
	}

	if want != got {
		return fmt.Errorf("invalid length for %s: expected %d, got %d", a, want, got)
	}
	return nil
}

func decodeChecksum(a ChecksumAlgorithm, v []byte) ([]byte, error) {
	if err := testChecksumLen(a, v); err != nil {
		return nil, err
	}
	switch a {
	case algorithmHashedPayload:
		dst := make([]byte, hex.DecodedLen(len(v)))
		n, err := hex.Decode(dst, v)
		return dst[:n], err
	default:
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(v)))
		n, err := base64.StdEncoding.Decode(dst, v)
		return dst[:n], err
	}
}

func decodeChecksumString(a ChecksumAlgorithm, v string) ([]byte, error) {
	if err := testChecksumLen(a, []byte(v)); err != nil {
		return nil, err
	}
	switch a {
	case algorithmHashedPayload:
		return hex.DecodeString(v)
	default:
		return base64.StdEncoding.DecodeString(v)
	}
}
