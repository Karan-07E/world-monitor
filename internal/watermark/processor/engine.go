// Package processor provides the complete DWT-DCT-QIM-RS watermark engine.
package processor

import (
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"math"

	"github.com/cryptoattr/secure-doc-dist/internal/watermark/dct"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/dwt"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/payload"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/qim"
	"github.com/cryptoattr/secure-doc-dist/internal/watermark/reedsolomon"
)

const (
	// Algorithm identifier for this watermark engine.
	Algorithm = "DWT-DCT-QIM-RS"

	// RSDataShards is the number of RS data shards.
	RSDataShards = 93 // payload size in bytes

	// RSParityShards is the number of RS parity shards.
	RSParityShards = 32 // allows correcting up to 16 symbol errors

	// QIMDelta is the quantization step.
	QIMDelta = 30.0

	// DCTCoeffRow and DCTCoeffCol are the mid-frequency DCT coefficient positions.
	DCTCoeffRow = 3
	DCTCoeffCol = 4

	// InterleaveInfo is used as context for interleaving.
	InterleaveInfo = "watermark-interleave-v1"
)

// Engine implements the DWT-DCT-QIM-RS watermark embedding and extraction.
type Engine struct {
	rsCodec *reedsolomon.Codec
	delta   float64
}

// NewEngine creates a new watermark engine.
func NewEngine() (*Engine, error) {
	rs, err := reedsolomon.NewCodec(RSDataShards, RSParityShards)
	if err != nil {
		return nil, fmt.Errorf("creating RS codec: %w", err)
	}

	return &Engine{
		rsCodec: rs,
		delta:   QIMDelta,
	}, nil
}

// ExtractionResult holds the result of watermark extraction.
type ExtractionResult struct {
	Found            bool
	Payload          *payload.WatermarkPayload
	BitErrorRate     float64
	RSCorrections    int
	ChecksumValid    bool
	Confidence       float64
	RawBitsExtracted int
}

// EmbedInImage embeds a watermark payload into an image.
func (e *Engine) EmbedInImage(img image.Image, p *payload.WatermarkPayload) (image.Image, error) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width < 64 || height < 64 {
		return nil, fmt.Errorf("image too small for watermarking: %dx%d", width, height)
	}

	// 1. Convert image to float64 luminance channel (Y from YCbCr)
	yChannel, cbChannel, crChannel := imageToYCbCr(img)

	// 2. Pad to even dimensions
	yPadded := dwt.PadToEven(yChannel)

	// 3. Forward DWT
	coeffs, err := dwt.Forward2D(yPadded)
	if err != nil {
		return nil, fmt.Errorf("DWT forward: %w", err)
	}

	// 4. Prepare payload bits
	// RS encode
	payloadBytes := p.Serialize()
	encoded, err := e.rsCodec.Encode(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("RS encoding: %w", err)
	}

	// Convert to bits
	bits := bytesToBits(encoded)

	// Interleave
	seed := sha256.Sum256([]byte(InterleaveInfo))
	interleaved := payload.Interleave(bits, seed[:])

	// 5. Embed in LL subband using DCT-QIM
	err = e.embedInSubband(coeffs.LL, interleaved)
	if err != nil {
		return nil, fmt.Errorf("embedding watermark: %w", err)
	}

	// 6. Inverse DWT
	reconstructed, err := dwt.Inverse2D(coeffs)
	if err != nil {
		return nil, fmt.Errorf("DWT inverse: %w", err)
	}

	// 7. Clip to original dimensions
	yResult := clipToSize(reconstructed, height, width)

	// 8. Convert back to image
	result := yCbCrToImage(yResult, cbChannel, crChannel, width, height)

	return result, nil
}

// ExtractFromImage extracts a watermark from an image.
func (e *Engine) ExtractFromImage(img image.Image) (*ExtractionResult, error) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width < 64 || height < 64 {
		return &ExtractionResult{Found: false}, nil
	}

	// 1. Convert to luminance
	yChannel, _, _ := imageToYCbCr(img)

	// 2. Pad
	yPadded := dwt.PadToEven(yChannel)

	// 3. Forward DWT
	coeffs, err := dwt.Forward2D(yPadded)
	if err != nil {
		return nil, fmt.Errorf("DWT forward: %w", err)
	}

	// 4. Calculate expected bit count
	totalBytes := RSDataShards + RSParityShards
	totalBits := totalBytes * 8

	// 5. Extract from LL subband
	rawBits, err := e.extractFromSubband(coeffs.LL, totalBits)
	if err != nil {
		return &ExtractionResult{Found: false, RawBitsExtracted: len(rawBits)}, nil
	}

	// 6. Deinterleave
	seed := sha256.Sum256([]byte(InterleaveInfo))
	deinterleaved := payload.Deinterleave(rawBits, seed[:])

	// 7. Convert bits to bytes
	rsEncoded := payload.BitsToBytes(deinterleaved)

	// 8. RS decode
	if len(rsEncoded) < totalBytes {
		padded := make([]byte, totalBytes)
		copy(padded, rsEncoded)
		rsEncoded = padded
	}

	decoded, corrections, err := e.rsCodec.Decode(rsEncoded[:totalBytes])
	if err != nil {
		return &ExtractionResult{
			Found:            false,
			RSCorrections:    0,
			RawBitsExtracted: len(rawBits),
			Confidence:       0.0,
		}, nil
	}

	// 9. Deserialize payload
	p, err := payload.Deserialize(decoded)
	if err != nil {
		return &ExtractionResult{
			Found:            false,
			RSCorrections:    corrections,
			RawBitsExtracted: len(rawBits),
		}, nil
	}

	// 10. Verify checksum
	checksumValid := p.Verify()

	// Calculate confidence
	confidence := 1.0
	if corrections > 0 {
		confidence = math.Max(0, 1.0-float64(corrections)/float64(RSParityShards))
	}
	if !checksumValid {
		confidence *= 0.1
	}

	return &ExtractionResult{
		Found:            checksumValid,
		Payload:          p,
		RSCorrections:    corrections,
		ChecksumValid:    checksumValid,
		Confidence:       confidence,
		RawBitsExtracted: len(rawBits),
	}, nil
}

// embedInSubband embeds bits into a DWT subband using DCT-QIM.
func (e *Engine) embedInSubband(subband [][]float64, bits []int) error {
	rows := len(subband)
	if rows == 0 {
		return fmt.Errorf("empty subband")
	}
	cols := len(subband[0])

	blockRows := rows / dct.BlockSize
	blockCols := cols / dct.BlockSize
	totalBlocks := blockRows * blockCols

	if totalBlocks < len(bits) {
		return fmt.Errorf("not enough blocks (%d) for %d bits", totalBlocks, len(bits))
	}

	bitIdx := 0
	for br := 0; br < blockRows && bitIdx < len(bits); br++ {
		for bc := 0; bc < blockCols && bitIdx < len(bits); bc++ {
			startRow := br * dct.BlockSize
			startCol := bc * dct.BlockSize

			// Extract block
			block := dct.ExtractBlock(subband, startRow, startCol)

			// Forward DCT
			dctBlock := dct.Forward2D(block)

			// Embed bit using QIM on mid-frequency coefficient
			dctBlock[DCTCoeffRow][DCTCoeffCol] = qim.EmbedBit(
				dctBlock[DCTCoeffRow][DCTCoeffCol],
				bits[bitIdx],
				e.delta,
			)

			// Inverse DCT
			reconstructed := dct.Inverse2D(dctBlock)

			// Insert back
			dct.InsertBlock(subband, reconstructed, startRow, startCol)

			bitIdx++
		}
	}

	return nil
}

// extractFromSubband extracts bits from a DWT subband using DCT-QIM.
func (e *Engine) extractFromSubband(subband [][]float64, numBits int) ([]int, error) {
	rows := len(subband)
	if rows == 0 {
		return nil, fmt.Errorf("empty subband")
	}
	cols := len(subband[0])

	blockRows := rows / dct.BlockSize
	blockCols := cols / dct.BlockSize

	bits := make([]int, 0, numBits)
	bitIdx := 0

	for br := 0; br < blockRows && bitIdx < numBits; br++ {
		for bc := 0; bc < blockCols && bitIdx < numBits; bc++ {
			startRow := br * dct.BlockSize
			startCol := bc * dct.BlockSize

			block := dct.ExtractBlock(subband, startRow, startCol)
			dctBlock := dct.Forward2D(block)

			bit := qim.ExtractBit(dctBlock[DCTCoeffRow][DCTCoeffCol], e.delta)
			bits = append(bits, bit)
			bitIdx++
		}
	}

	return bits, nil
}

// imageToYCbCr converts an image to Y, Cb, Cr float64 channels.
func imageToYCbCr(img image.Image) ([][]float64, [][]float64, [][]float64) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	y := make([][]float64, height)
	cb := make([][]float64, height)
	cr := make([][]float64, height)

	for i := 0; i < height; i++ {
		y[i] = make([]float64, width)
		cb[i] = make([]float64, width)
		cr[i] = make([]float64, width)

		for j := 0; j < width; j++ {
			r, g, b, _ := img.At(bounds.Min.X+j, bounds.Min.Y+i).RGBA()
			rf := float64(r) / 256.0
			gf := float64(g) / 256.0
			bf := float64(b) / 256.0

			y[i][j] = 0.299*rf + 0.587*gf + 0.114*bf
			cb[i][j] = -0.168736*rf - 0.331264*gf + 0.5*bf + 128
			cr[i][j] = 0.5*rf - 0.418688*gf - 0.081312*bf + 128
		}
	}

	return y, cb, cr
}

// yCbCrToImage converts Y, Cb, Cr channels back to an RGBA image.
func yCbCrToImage(yc, cb, cr [][]float64, width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for i := 0; i < height; i++ {
		for j := 0; j < width; j++ {
			yVal := yc[i][j]
			cbVal := cb[i][j] - 128
			crVal := cr[i][j] - 128

			r := yVal + 1.402*crVal
			g := yVal - 0.344136*cbVal - 0.714136*crVal
			b := yVal + 1.772*cbVal

			img.Set(j, i, color.RGBA{
				R: clampByte(r),
				G: clampByte(g),
				B: clampByte(b),
				A: 255,
			})
		}
	}

	return img
}

func clampByte(v float64) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(math.Round(v))
}

func clipToSize(data [][]float64, rows, cols int) [][]float64 {
	result := make([][]float64, rows)
	for i := 0; i < rows; i++ {
		if i < len(data) {
			result[i] = make([]float64, cols)
			n := cols
			if n > len(data[i]) {
				n = len(data[i])
			}
			copy(result[i], data[i][:n])
		} else {
			result[i] = make([]float64, cols)
		}
	}
	return result
}

func bytesToBits(data []byte) []int {
	bits := make([]int, len(data)*8)
	for i, b := range data {
		for j := 7; j >= 0; j-- {
			bits[i*8+(7-j)] = int((b >> uint(j)) & 1)
		}
	}
	return bits
}
