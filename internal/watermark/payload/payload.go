// Package payload provides watermark payload construction, serialization, and interleaving.
package payload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	// PayloadVersion is the current payload format version.
	PayloadVersion = 1

	// WatermarkIDSize is the size of the watermark ID in bytes.
	WatermarkIDSize = 32

	// SessionIDSize is the size of the session ID in bytes.
	SessionIDSize = 32

	// NonceSize is the size of the random nonce in bytes.
	NonceSize = 16

	// DocHashSize is the truncated document hash size in bytes.
	DocHashSize = 8
)

// WatermarkPayload represents the data embedded in a forensic watermark.
type WatermarkPayload struct {
	Version       byte     `json:"version"`
	DocIDHash     [DocHashSize]byte `json:"doc_id_hash"`
	SessionID     [SessionIDSize]byte `json:"session_id"`
	WatermarkID   [WatermarkIDSize]byte `json:"watermark_id"`
	RandomNonce   [NonceSize]byte `json:"random_nonce"`
	Checksum      uint32   `json:"checksum"`
}

// NewPayload creates a new watermark payload.
func NewPayload(documentHash []byte, sessionIDBytes, watermarkIDBytes []byte) (*WatermarkPayload, error) {
	p := &WatermarkPayload{
		Version: PayloadVersion,
	}

	// Truncated document hash
	if len(documentHash) >= DocHashSize {
		copy(p.DocIDHash[:], documentHash[:DocHashSize])
	}

	// Session ID
	if len(sessionIDBytes) >= SessionIDSize {
		copy(p.SessionID[:], sessionIDBytes[:SessionIDSize])
	} else {
		copy(p.SessionID[:], sessionIDBytes)
	}

	// Watermark ID
	if len(watermarkIDBytes) >= WatermarkIDSize {
		copy(p.WatermarkID[:], watermarkIDBytes[:WatermarkIDSize])
	} else {
		copy(p.WatermarkID[:], watermarkIDBytes)
	}

	// Random nonce
	if _, err := io.ReadFull(rand.Reader, p.RandomNonce[:]); err != nil {
		return nil, fmt.Errorf("generating random nonce: %w", err)
	}

	// Compute checksum
	p.Checksum = p.computeChecksum()

	return p, nil
}

// Serialize converts the payload to bytes.
func (p *WatermarkPayload) Serialize() []byte {
	// Layout: version(1) + docHash(8) + sessionID(32) + watermarkID(32) + nonce(16) + checksum(4) = 93 bytes
	buf := make([]byte, 0, 93)
	buf = append(buf, p.Version)
	buf = append(buf, p.DocIDHash[:]...)
	buf = append(buf, p.SessionID[:]...)
	buf = append(buf, p.WatermarkID[:]...)
	buf = append(buf, p.RandomNonce[:]...)

	cs := make([]byte, 4)
	binary.BigEndian.PutUint32(cs, p.Checksum)
	buf = append(buf, cs...)

	return buf
}

// Deserialize reconstructs a payload from bytes.
func Deserialize(data []byte) (*WatermarkPayload, error) {
	if len(data) < 93 {
		return nil, fmt.Errorf("payload too short: %d bytes", len(data))
	}

	p := &WatermarkPayload{}
	offset := 0

	p.Version = data[offset]
	offset++

	copy(p.DocIDHash[:], data[offset:offset+DocHashSize])
	offset += DocHashSize

	copy(p.SessionID[:], data[offset:offset+SessionIDSize])
	offset += SessionIDSize

	copy(p.WatermarkID[:], data[offset:offset+WatermarkIDSize])
	offset += WatermarkIDSize

	copy(p.RandomNonce[:], data[offset:offset+NonceSize])
	offset += NonceSize

	p.Checksum = binary.BigEndian.Uint32(data[offset : offset+4])

	return p, nil
}

// Verify checks the payload checksum.
func (p *WatermarkPayload) Verify() bool {
	return p.Checksum == p.computeChecksum()
}

// computeChecksum computes CRC32 over the payload fields (excluding the checksum itself).
func (p *WatermarkPayload) computeChecksum() uint32 {
	buf := make([]byte, 0, 89)
	buf = append(buf, p.Version)
	buf = append(buf, p.DocIDHash[:]...)
	buf = append(buf, p.SessionID[:]...)
	buf = append(buf, p.WatermarkID[:]...)
	buf = append(buf, p.RandomNonce[:]...)
	return crc32.ChecksumIEEE(buf)
}

// ToBits converts the serialized payload to a bit array.
func (p *WatermarkPayload) ToBits() []int {
	data := p.Serialize()
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 7; j >= 0; j-- {
			bits[i*8+(7-j)] = int((b >> uint(j)) & 1)
		}
	}
	return bits
}

// BitsToBytes converts a bit array back to bytes.
func BitsToBytes(bits []int) []byte {
	nBytes := (len(bits) + 7) / 8
	result := make([]byte, nBytes)
	for i, bit := range bits {
		if bit == 1 {
			byteIdx := i / 8
			bitIdx := 7 - (i % 8)
			result[byteIdx] |= 1 << uint(bitIdx)
		}
	}
	return result
}

// Hash computes SHA-256 of the serialized payload.
func (p *WatermarkPayload) Hash() []byte {
	data := p.Serialize()
	h := sha256.Sum256(data)
	return h[:]
}

// Interleave pseudo-randomly interleaves bits using a seed.
func Interleave(bits []int, seed []byte) []int {
	n := len(bits)
	if n == 0 {
		return bits
	}

	// Generate permutation from seed using Fisher-Yates
	perm := makePermutation(n, seed)
	result := make([]int, n)
	for i, p := range perm {
		result[p] = bits[i]
	}
	return result
}

// Deinterleave reverses the interleaving.
func Deinterleave(bits []int, seed []byte) []int {
	n := len(bits)
	if n == 0 {
		return bits
	}

	perm := makePermutation(n, seed)
	result := make([]int, n)
	for i, p := range perm {
		result[i] = bits[p]
	}
	return result
}

// makePermutation generates a deterministic permutation from a seed.
func makePermutation(n int, seed []byte) []int {
	perm := make([]int, n)
	for i := range perm {
		perm[i] = i
	}

	// Use SHA-256 based PRNG for deterministic permutation
	state := sha256.Sum256(seed)
	counter := 0

	for i := n - 1; i > 0; i-- {
		// Generate pseudo-random index
		if counter%32 == 0 && counter > 0 {
			combined := make([]byte, 32+4)
			copy(combined, state[:])
			binary.BigEndian.PutUint32(combined[32:], uint32(counter))
			state = sha256.Sum256(combined)
		}

		j := int(binary.BigEndian.Uint32(state[counter%32:counter%32+4])) % (i + 1)
		if counter%32 >= 28 {
			// Need to refresh state
			combined := make([]byte, 32+4)
			copy(combined, state[:])
			binary.BigEndian.PutUint32(combined[32:], uint32(counter))
			state = sha256.Sum256(combined)
			counter = 0
		} else {
			counter += 4
		}

		perm[i], perm[j] = perm[j], perm[i]
	}

	return perm
}
