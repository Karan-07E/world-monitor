// Package dwt provides Discrete Wavelet Transform operations for watermarking.
package dwt

import (
	"fmt"
	"math"
)

// Coefficients holds the DWT decomposition of an image channel.
type Coefficients struct {
	LL     [][]float64 // Approximation
	LH     [][]float64 // Horizontal detail
	HL     [][]float64 // Vertical detail
	HH     [][]float64 // Diagonal detail
	Width  int
	Height int
}

// Forward2D performs a single-level 2D Haar DWT on a 2D float64 array.
func Forward2D(data [][]float64) (*Coefficients, error) {
	rows := len(data)
	if rows == 0 {
		return nil, fmt.Errorf("empty input data")
	}
	cols := len(data[0])
	if cols == 0 {
		return nil, fmt.Errorf("empty input row")
	}

	// Ensure even dimensions
	if rows%2 != 0 || cols%2 != 0 {
		return nil, fmt.Errorf("dimensions must be even: got %dx%d", rows, cols)
	}

	halfRows := rows / 2
	halfCols := cols / 2

	// Step 1: Apply 1D DWT along rows
	rowTransformed := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		rowTransformed[i] = make([]float64, cols)
		for j := 0; j < halfCols; j++ {
			a := data[i][2*j]
			b := data[i][2*j+1]
			rowTransformed[i][j] = (a + b) / math.Sqrt2
			rowTransformed[i][j+halfCols] = (a - b) / math.Sqrt2
		}
	}

	// Step 2: Apply 1D DWT along columns
	ll := make([][]float64, halfRows)
	lh := make([][]float64, halfRows)
	hl := make([][]float64, halfRows)
	hh := make([][]float64, halfRows)

	for i := 0; i < halfRows; i++ {
		ll[i] = make([]float64, halfCols)
		lh[i] = make([]float64, halfCols)
		hl[i] = make([]float64, halfCols)
		hh[i] = make([]float64, halfCols)

		for j := 0; j < halfCols; j++ {
			a := rowTransformed[2*i][j]
			b := rowTransformed[2*i+1][j]
			ll[i][j] = (a + b) / math.Sqrt2
			hl[i][j] = (a - b) / math.Sqrt2

			c := rowTransformed[2*i][j+halfCols]
			d := rowTransformed[2*i+1][j+halfCols]
			lh[i][j] = (c + d) / math.Sqrt2
			hh[i][j] = (c - d) / math.Sqrt2
		}
	}

	return &Coefficients{
		LL:     ll,
		LH:     lh,
		HL:     hl,
		HH:     hh,
		Width:  cols,
		Height: rows,
	}, nil
}

// Inverse2D performs the inverse 2D Haar DWT to reconstruct the data.
func Inverse2D(coeff *Coefficients) ([][]float64, error) {
	if coeff == nil {
		return nil, fmt.Errorf("nil coefficients")
	}

	halfRows := len(coeff.LL)
	if halfRows == 0 {
		return nil, fmt.Errorf("empty LL band")
	}
	halfCols := len(coeff.LL[0])

	rows := halfRows * 2
	cols := halfCols * 2

	// Step 1: Inverse along columns
	rowTransformed := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		rowTransformed[i] = make([]float64, cols)
	}

	for i := 0; i < halfRows; i++ {
		for j := 0; j < halfCols; j++ {
			a := coeff.LL[i][j]
			b := coeff.HL[i][j]
			rowTransformed[2*i][j] = (a + b) / math.Sqrt2
			rowTransformed[2*i+1][j] = (a - b) / math.Sqrt2

			c := coeff.LH[i][j]
			d := coeff.HH[i][j]
			rowTransformed[2*i][j+halfCols] = (c + d) / math.Sqrt2
			rowTransformed[2*i+1][j+halfCols] = (c - d) / math.Sqrt2
		}
	}

	// Step 2: Inverse along rows
	result := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		result[i] = make([]float64, cols)
		for j := 0; j < halfCols; j++ {
			a := rowTransformed[i][j]
			b := rowTransformed[i][j+halfCols]
			result[i][2*j] = (a + b) / math.Sqrt2
			result[i][2*j+1] = (a - b) / math.Sqrt2
		}
	}

	return result, nil
}

// PadToEven pads the input to even dimensions if needed.
func PadToEven(data [][]float64) [][]float64 {
	rows := len(data)
	if rows == 0 {
		return data
	}
	cols := len(data[0])

	newRows := rows
	newCols := cols
	if rows%2 != 0 {
		newRows = rows + 1
	}
	if cols%2 != 0 {
		newCols = cols + 1
	}

	if newRows == rows && newCols == cols {
		return data
	}

	padded := make([][]float64, newRows)
	for i := 0; i < newRows; i++ {
		padded[i] = make([]float64, newCols)
		if i < rows {
			copy(padded[i], data[i])
			if newCols > cols {
				padded[i][cols] = data[i][cols-1] // mirror
			}
		} else {
			copy(padded[i], data[rows-1]) // mirror last row
		}
	}
	return padded
}
