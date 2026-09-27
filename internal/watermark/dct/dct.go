// Package dct provides Discrete Cosine Transform operations for watermarking.
package dct

import (
	"math"
)

// BlockSize is the standard DCT block size.
const BlockSize = 8

// Forward2D computes the 2D DCT-II of an 8x8 block.
func Forward2D(block [BlockSize][BlockSize]float64) [BlockSize][BlockSize]float64 {
	var result [BlockSize][BlockSize]float64
	n := float64(BlockSize)

	for u := 0; u < BlockSize; u++ {
		for v := 0; v < BlockSize; v++ {
			sum := 0.0
			for x := 0; x < BlockSize; x++ {
				for y := 0; y < BlockSize; y++ {
					cosX := math.Cos((2.0*float64(x) + 1.0) * float64(u) * math.Pi / (2.0 * n))
					cosY := math.Cos((2.0*float64(y) + 1.0) * float64(v) * math.Pi / (2.0 * n))
					sum += block[x][y] * cosX * cosY
				}
			}
			cu := 1.0
			cv := 1.0
			if u == 0 {
				cu = 1.0 / math.Sqrt2
			}
			if v == 0 {
				cv = 1.0 / math.Sqrt2
			}
			result[u][v] = 0.25 * cu * cv * sum
		}
	}
	return result
}

// Inverse2D computes the 2D IDCT-II of an 8x8 block.
func Inverse2D(dctBlock [BlockSize][BlockSize]float64) [BlockSize][BlockSize]float64 {
	var result [BlockSize][BlockSize]float64
	n := float64(BlockSize)

	for x := 0; x < BlockSize; x++ {
		for y := 0; y < BlockSize; y++ {
			sum := 0.0
			for u := 0; u < BlockSize; u++ {
				for v := 0; v < BlockSize; v++ {
					cu := 1.0
					cv := 1.0
					if u == 0 {
						cu = 1.0 / math.Sqrt2
					}
					if v == 0 {
						cv = 1.0 / math.Sqrt2
					}
					cosX := math.Cos((2.0*float64(x) + 1.0) * float64(u) * math.Pi / (2.0 * n))
					cosY := math.Cos((2.0*float64(y) + 1.0) * float64(v) * math.Pi / (2.0 * n))
					sum += cu * cv * dctBlock[u][v] * cosX * cosY
				}
			}
			result[x][y] = 0.25 * sum
		}
	}
	return result
}

// ExtractBlock extracts an 8x8 block from a 2D array starting at (startRow, startCol).
func ExtractBlock(data [][]float64, startRow, startCol int) [BlockSize][BlockSize]float64 {
	var block [BlockSize][BlockSize]float64
	rows := len(data)
	cols := 0
	if rows > 0 {
		cols = len(data[0])
	}

	for i := 0; i < BlockSize; i++ {
		for j := 0; j < BlockSize; j++ {
			r := startRow + i
			c := startCol + j
			if r < rows && c < cols {
				block[i][j] = data[r][c]
			}
		}
	}
	return block
}

// InsertBlock inserts an 8x8 block into a 2D array starting at (startRow, startCol).
func InsertBlock(data [][]float64, block [BlockSize][BlockSize]float64, startRow, startCol int) {
	rows := len(data)
	cols := 0
	if rows > 0 {
		cols = len(data[0])
	}

	for i := 0; i < BlockSize; i++ {
		for j := 0; j < BlockSize; j++ {
			r := startRow + i
			c := startCol + j
			if r < rows && c < cols {
				data[r][c] = block[i][j]
			}
		}
	}
}
