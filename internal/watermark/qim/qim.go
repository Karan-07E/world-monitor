// Package qim provides Quantization Index Modulation for watermark embedding.
package qim

import (
	"math"
)

// DefaultDelta is the default quantization step size.
// Larger values increase robustness but may reduce quality.
const DefaultDelta = 25.0

// EmbedBit embeds a single bit into a DCT coefficient using QIM.
// The coefficient is quantized to the nearest value that encodes the desired bit.
func EmbedBit(coefficient float64, bit int, delta float64) float64 {
	if delta <= 0 {
		delta = DefaultDelta
	}

	// Two quantization codebooks:
	// Codebook 0: quantize to nearest even multiple of delta/2
	// Codebook 1: quantize to nearest odd multiple of delta/2
	halfDelta := delta / 2.0

	// Quantize to nearest multiple of delta
	q := math.Round(coefficient / delta)

	// Determine the codebook based on the bit
	if bit == 0 {
		// Even quantization index
		qi := q
		if int(math.Abs(qi))%2 != 0 {
			// Adjust to nearest even
			if coefficient > qi*delta {
				qi++
			} else {
				qi--
			}
		}
		return qi * delta
	}

	// bit == 1: Odd quantization index
	qi := q
	if int(math.Abs(qi))%2 == 0 {
		// Adjust to nearest odd
		if coefficient > qi*delta {
			qi++
		} else {
			qi--
		}
	}
	_ = halfDelta
	return qi * delta
}

// ExtractBit extracts a single bit from a DCT coefficient using QIM.
func ExtractBit(coefficient float64, delta float64) int {
	if delta <= 0 {
		delta = DefaultDelta
	}

	q := math.Round(coefficient / delta)
	qi := int(math.Abs(q))

	if qi%2 == 0 {
		return 0
	}
	return 1
}

// EmbedBits embeds multiple bits into a slice of DCT coefficients.
// Returns the modified coefficients.
func EmbedBits(coefficients []float64, bits []int, delta float64) []float64 {
	result := make([]float64, len(coefficients))
	copy(result, coefficients)

	n := len(bits)
	if n > len(coefficients) {
		n = len(coefficients)
	}

	for i := 0; i < n; i++ {
		result[i] = EmbedBit(coefficients[i], bits[i], delta)
	}
	return result
}

// ExtractBits extracts multiple bits from DCT coefficients.
func ExtractBits(coefficients []float64, count int, delta float64) []int {
	bits := make([]int, count)
	n := count
	if n > len(coefficients) {
		n = len(coefficients)
	}

	for i := 0; i < n; i++ {
		bits[i] = ExtractBit(coefficients[i], delta)
	}
	return bits
}
