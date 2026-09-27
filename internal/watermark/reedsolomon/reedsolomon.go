// Package reedsolomon provides Reed-Solomon error correction for watermark payloads.
package reedsolomon

import (
	"fmt"
)

// Codec provides Reed-Solomon encoding and decoding.
// This is a simplified RS implementation using GF(2^8) for watermark payloads.
type Codec struct {
	dataShards   int
	parityShards int
	totalShards  int
	gfExp        [512]byte
	gfLog        [256]byte
	generator    []byte
}

// NewCodec creates a new Reed-Solomon codec.
// dataShards: number of data bytes
// parityShards: number of parity bytes (error correction capacity = parityShards/2)
func NewCodec(dataShards, parityShards int) (*Codec, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, fmt.Errorf("shard counts must be positive")
	}
	if dataShards+parityShards > 255 {
		return nil, fmt.Errorf("total shards must be <= 255")
	}

	c := &Codec{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
	c.initGaloisField()
	c.initGenerator()
	return c, nil
}

// initGaloisField initializes the GF(2^8) lookup tables with primitive polynomial 0x11d.
func (c *Codec) initGaloisField() {
	primitive := 0x11d
	x := 1
	for i := 0; i < 255; i++ {
		c.gfExp[i] = byte(x)
		c.gfLog[x] = byte(i)
		x <<= 1
		if x >= 256 {
			x ^= primitive
		}
	}
	for i := 255; i < 512; i++ {
		c.gfExp[i] = c.gfExp[i-255]
	}
}

func (c *Codec) gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return c.gfExp[int(c.gfLog[a])+int(c.gfLog[b])]
}

func (c *Codec) gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	if a == 0 {
		return 0
	}
	return c.gfExp[(int(c.gfLog[a])-int(c.gfLog[b])+255)%255]
}

func (c *Codec) gfPow(x byte, power int) byte {
	if x == 0 {
		return 0
	}
	return c.gfExp[(int(c.gfLog[x])*power)%255]
}

func (c *Codec) gfInverse(x byte) byte {
	if x == 0 {
		return 0
	}
	return c.gfExp[255-int(c.gfLog[x])]
}

// initGenerator builds the generator polynomial.
func (c *Codec) initGenerator() {
	c.generator = make([]byte, c.parityShards+1)
	c.generator[0] = 1

	for i := 0; i < c.parityShards; i++ {
		// Multiply by (x - alpha^i)
		newGen := make([]byte, len(c.generator))
		for j := len(c.generator) - 1; j > 0; j-- {
			newGen[j] = c.generator[j-1] ^ c.gfMul(c.generator[j], c.gfExp[i])
		}
		newGen[0] = c.gfMul(c.generator[0], c.gfExp[i])
		c.generator = newGen
	}
}

// Encode adds Reed-Solomon parity bytes to the data.
func (c *Codec) Encode(data []byte) ([]byte, error) {
	if len(data) != c.dataShards {
		return nil, fmt.Errorf("data length %d != expected %d", len(data), c.dataShards)
	}

	// Create message polynomial
	msg := make([]byte, c.totalShards)
	copy(msg, data)

	// Polynomial division
	for i := 0; i < c.dataShards; i++ {
		coeff := msg[i]
		if coeff != 0 {
			for j := 1; j < len(c.generator); j++ {
				msg[i+j] ^= c.gfMul(c.generator[j], coeff)
			}
		}
	}

	// Result is data + parity
	result := make([]byte, c.totalShards)
	copy(result, data)
	copy(result[c.dataShards:], msg[c.dataShards:])

	return result, nil
}

// Decode attempts to decode and correct errors in the received data.
// Returns the corrected data (data shards only) and the number of errors corrected.
func (c *Codec) Decode(received []byte) ([]byte, int, error) {
	if len(received) != c.totalShards {
		return nil, 0, fmt.Errorf("received length %d != expected %d", len(received), c.totalShards)
	}

	// Calculate syndromes
	syndromes := make([]byte, c.parityShards)
	hasErrors := false
	for i := 0; i < c.parityShards; i++ {
		s := byte(0)
		for j := 0; j < c.totalShards; j++ {
			s = c.gfMul(s, c.gfExp[i]) ^ received[j]
		}
		syndromes[i] = s
		if s != 0 {
			hasErrors = true
		}
	}

	if !hasErrors {
		result := make([]byte, c.dataShards)
		copy(result, received[:c.dataShards])
		return result, 0, nil
	}

	// Berlekamp-Massey algorithm to find error locator polynomial
	errLoc, err := c.berlekampMassey(syndromes)
	if err != nil {
		return nil, 0, fmt.Errorf("error locator computation failed: %w", err)
	}

	// Find error positions using Chien search
	errPos, err := c.chienSearch(errLoc)
	if err != nil {
		return nil, 0, fmt.Errorf("error position search failed: %w", err)
	}

	// Forney algorithm to find error values
	corrected := make([]byte, len(received))
	copy(corrected, received)

	errEval := c.computeErrorEvaluator(syndromes, errLoc)

	for _, pos := range errPos {
		actualPos := c.totalShards - 1 - pos
		if actualPos < 0 || actualPos >= c.totalShards {
			return nil, 0, fmt.Errorf("invalid error position: %d", actualPos)
		}

		xi := c.gfExp[pos]
		xiInv := c.gfInverse(xi)

		// Evaluate error evaluator at xi_inverse
		errEvalVal := byte(0)
		for j := 0; j < len(errEval); j++ {
			errEvalVal ^= c.gfMul(errEval[j], c.gfPow(xiInv, j))
		}

		// Evaluate error locator derivative at xi_inverse
		errLocDeriv := byte(0)
		for j := 1; j < len(errLoc); j += 2 {
			errLocDeriv ^= c.gfMul(errLoc[j], c.gfPow(xiInv, j-1))
		}

		if errLocDeriv == 0 {
			return nil, 0, fmt.Errorf("error locator derivative is zero")
		}

		magnitude := c.gfDiv(errEvalVal, errLocDeriv)
		corrected[actualPos] ^= magnitude
	}

	result := make([]byte, c.dataShards)
	copy(result, corrected[:c.dataShards])
	return result, len(errPos), nil
}

func (c *Codec) berlekampMassey(syndromes []byte) ([]byte, error) {
	n := len(syndromes)
	errLoc := []byte{1}
	oldLoc := []byte{1}

	for i := 0; i < n; i++ {
		delta := syndromes[i]
		for j := 1; j < len(errLoc); j++ {
			delta ^= c.gfMul(errLoc[j], syndromes[i-j])
		}

		oldLoc = append(oldLoc, 0)

		if delta != 0 {
			if len(oldLoc) > len(errLoc) {
				newLoc := make([]byte, len(oldLoc))
				for j := range oldLoc {
					newLoc[j] = c.gfMul(oldLoc[j], delta)
				}
				oldLoc = make([]byte, len(errLoc))
				for j := range errLoc {
					oldLoc[j] = c.gfMul(errLoc[j], c.gfInverse(delta))
				}
				errLoc = newLoc
			}

			for j := range oldLoc {
				if j < len(errLoc) {
					errLoc[j] ^= c.gfMul(oldLoc[j], delta)
				}
			}
		}
	}

	return errLoc, nil
}

func (c *Codec) chienSearch(errLoc []byte) ([]int, error) {
	numErrors := len(errLoc) - 1
	positions := make([]int, 0, numErrors)

	for i := 0; i < c.totalShards; i++ {
		val := byte(0)
		for j := 0; j < len(errLoc); j++ {
			val ^= c.gfMul(errLoc[j], c.gfPow(c.gfExp[i], j))
		}
		if val == 0 {
			positions = append(positions, i)
		}
	}

	if len(positions) != numErrors {
		return nil, fmt.Errorf("found %d error positions, expected %d", len(positions), numErrors)
	}

	return positions, nil
}

func (c *Codec) computeErrorEvaluator(syndromes []byte, errLoc []byte) []byte {
	product := make([]byte, len(syndromes)+len(errLoc))
	for i := range syndromes {
		for j := range errLoc {
			product[i+j] ^= c.gfMul(syndromes[i], errLoc[j])
		}
	}

	result := make([]byte, len(syndromes))
	n := len(syndromes)
	if n > len(product) {
		n = len(product)
	}
	copy(result, product[:n])
	return result
}

// DataShards returns the number of data shards.
func (c *Codec) DataShards() int { return c.dataShards }

// ParityShards returns the number of parity shards.
func (c *Codec) ParityShards() int { return c.parityShards }
