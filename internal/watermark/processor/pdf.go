// Package processor provides the DocumentProcessor interface and PDF implementation.
package processor

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"

	"github.com/cryptoattr/secure-doc-dist/internal/watermark/payload"
	"github.com/gen2brain/go-fitz"
)

// DocumentProcessor defines the interface for document format handling.
type DocumentProcessor interface {
	// ExtractPages extracts pages from a document as images.
	ExtractPages(docData []byte) ([]image.Image, error)

	// EmbedWatermark embeds a watermark into all pages.
	EmbedWatermark(docData []byte, p *payload.WatermarkPayload) ([]byte, error)

	// ExtractWatermark extracts a watermark from a document.
	ExtractWatermark(docData []byte) (*ExtractionResult, error)

	// Reconstruct builds a document from watermarked page images.
	Reconstruct(pages []image.Image, format string) ([]byte, error)
}

// PDFProcessor implements DocumentProcessor for PDF files.
type PDFProcessor struct {
	engine *Engine
	dpi    float64
}

// NewPDFProcessor creates a new PDF processor.
func NewPDFProcessor() (*PDFProcessor, error) {
	eng, err := NewEngine()
	if err != nil {
		return nil, err
	}
	return &PDFProcessor{
		engine: eng,
		dpi:    200.0, // 200 DPI for watermark embedding
	}, nil
}

// ExtractPages renders PDF pages as images.
func (p *PDFProcessor) ExtractPages(docData []byte) ([]image.Image, error) {
	doc, err := fitz.NewFromMemory(docData)
	if err != nil {
		return nil, fmt.Errorf("opening PDF: %w", err)
	}
	defer doc.Close()

	numPages := doc.NumPage()
	pages := make([]image.Image, 0, numPages)

	for i := 0; i < numPages; i++ {
		img, err := doc.ImageDPI(i, p.dpi)
		if err != nil {
			return nil, fmt.Errorf("rendering page %d: %w", i, err)
		}
		pages = append(pages, img)
	}

	return pages, nil
}

// EmbedWatermark embeds a watermark into a PDF.
func (p *PDFProcessor) EmbedWatermark(docData []byte, wp *payload.WatermarkPayload) ([]byte, error) {
	// 1. Extract pages
	pages, err := p.ExtractPages(docData)
	if err != nil {
		return nil, err
	}

	if len(pages) == 0 {
		return nil, fmt.Errorf("no pages in document")
	}

	// 2. Watermark each page
	watermarked := make([]image.Image, len(pages))
	for i, page := range pages {
		wm, err := p.engine.EmbedInImage(page, wp)
		if err != nil {
			return nil, fmt.Errorf("watermarking page %d: %w", i, err)
		}
		watermarked[i] = wm
	}

	// 3. Reconstruct as PDF
	return p.Reconstruct(watermarked, "pdf")
}

// ExtractWatermark extracts a watermark from a PDF document.
func (p *PDFProcessor) ExtractWatermark(docData []byte) (*ExtractionResult, error) {
	// 1. Extract pages
	pages, err := p.ExtractPages(docData)
	if err != nil {
		return nil, fmt.Errorf("extracting pages: %w", err)
	}

	if len(pages) == 0 {
		return &ExtractionResult{Found: false}, nil
	}

	// Try extracting from each page, return first successful result
	var bestResult *ExtractionResult
	for i, page := range pages {
		result, err := p.engine.ExtractFromImage(page)
		if err != nil {
			continue
		}
		if result.Found {
			return result, nil
		}
		// Keep the best result even if not found
		if bestResult == nil || (result.Confidence > bestResult.Confidence) {
			_ = i // suppress unused
			bestResult = result
		}
	}

	if bestResult != nil {
		return bestResult, nil
	}

	return &ExtractionResult{Found: false}, nil
}

// ExtractWatermarkFromImage extracts a watermark from an image (PNG/JPEG).
func (p *PDFProcessor) ExtractWatermarkFromImage(imgData []byte) (*ExtractionResult, error) {
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return nil, fmt.Errorf("decoding image: %w", err)
	}
	return p.engine.ExtractFromImage(img)
}

// Reconstruct builds a PDF from page images.
// For the demo, we output the watermarked pages as a multi-page JPEG/PNG collection
// wrapped in a simple PDF structure.
func (p *PDFProcessor) Reconstruct(pages []image.Image, format string) ([]byte, error) {
	if format == "pdf" {
		return p.reconstructPDF(pages)
	}
	return nil, fmt.Errorf("unsupported output format: %s", format)
}

// reconstructPDF creates a minimal PDF containing JPEG-encoded page images.
func (p *PDFProcessor) reconstructPDF(pages []image.Image) ([]byte, error) {
	var buf bytes.Buffer
	writer := &pdfWriter{w: &buf}

	if err := writer.writeHeader(); err != nil {
		return nil, err
	}

	// Encode all pages as JPEG images
	jpegDatas := make([][]byte, len(pages))
	for i, page := range pages {
		var imgBuf bytes.Buffer
		if err := jpeg.Encode(&imgBuf, page, &jpeg.Options{Quality: 95}); err != nil {
			return nil, fmt.Errorf("encoding page %d: %w", i, err)
		}
		jpegDatas[i] = imgBuf.Bytes()
	}

	if err := writer.writePages(pages, jpegDatas); err != nil {
		return nil, err
	}

	if err := writer.writeTrailer(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodePageAsPNG encodes an image page as PNG.
func EncodePageAsPNG(page image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, page); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodePageAsJPEG encodes an image page as JPEG.
func EncodePageAsJPEG(page image.Image, quality int) ([]byte, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, page, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// pdfWriter creates minimal valid PDF files from images.
type pdfWriter struct {
	w       io.Writer
	offsets []int64
	pos     int64
}

func (pw *pdfWriter) write(s string) error {
	n, err := fmt.Fprint(pw.w, s)
	pw.pos += int64(n)
	return err
}

func (pw *pdfWriter) writeBytes(b []byte) error {
	n, err := pw.w.Write(b)
	pw.pos += int64(n)
	return err
}

func (pw *pdfWriter) writeHeader() error {
	return pw.write("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
}

func (pw *pdfWriter) writePages(pages []image.Image, jpegDatas [][]byte) error {
	numPages := len(pages)

	// Object numbering:
	// 1: Catalog
	// 2: Pages
	// For each page i (0-indexed):
	//   3 + i*3: Page
	//   4 + i*3: Image XObject
	//   5 + i*3: Resources

	catalogObj := 1
	pagesObj := 2
	firstPageObj := 3

	// Build page refs
	pageRefs := ""
	for i := 0; i < numPages; i++ {
		pageObjNum := firstPageObj + i*3
		if i > 0 {
			pageRefs += " "
		}
		pageRefs += fmt.Sprintf("%d 0 R", pageObjNum)
	}

	// Catalog
	pw.offsets = append(pw.offsets, pw.pos)
	pw.write(fmt.Sprintf("%d 0 obj\n<< /Type /Catalog /Pages %d 0 R >>\nendobj\n", catalogObj, pagesObj))

	// Pages
	pw.offsets = append(pw.offsets, pw.pos)
	pw.write(fmt.Sprintf("%d 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n", pagesObj, pageRefs, numPages))

	// Each page
	for i := 0; i < numPages; i++ {
		bounds := pages[i].Bounds()
		w := bounds.Dx()
		h := bounds.Dy()
		pageW := float64(w) * 72.0 / pw.dpi()
		pageH := float64(h) * 72.0 / pw.dpi()

		pageObjNum := firstPageObj + i*3
		imgObjNum := firstPageObj + i*3 + 1
		contentObjNum := firstPageObj + i*3 + 2

		// Image XObject
		imgData := jpegDatas[i]
		pw.offsets = append(pw.offsets, pw.pos)
		pw.write(fmt.Sprintf("%d 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length %d >>\nstream\n",
			imgObjNum, w, h, len(imgData)))
		pw.writeBytes(imgData)
		pw.write("\nendstream\nendobj\n")

		// Content stream
		contentStr := fmt.Sprintf("q %.2f 0 0 %.2f 0 0 cm /Img%d Do Q", pageW, pageH, i)
		pw.offsets = append(pw.offsets, pw.pos)
		pw.write(fmt.Sprintf("%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
			contentObjNum, len(contentStr), contentStr))

		// Page
		pw.offsets = append(pw.offsets, pw.pos)
		pw.write(fmt.Sprintf("%d 0 obj\n<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Contents %d 0 R /Resources << /XObject << /Img%d %d 0 R >> >> >>\nendobj\n",
			pageObjNum, pagesObj, pageW, pageH, contentObjNum, i, imgObjNum))
	}

	return nil
}

func (pw *pdfWriter) dpi() float64 {
	return 200.0
}

func (pw *pdfWriter) writeTrailer() error {
	xrefPos := pw.pos
	numObjects := len(pw.offsets) + 1

	pw.write(fmt.Sprintf("xref\n0 %d\n", numObjects))
	pw.write("0000000000 65535 f \n")
	for _, offset := range pw.offsets {
		pw.write(fmt.Sprintf("%010d 00000 n \n", offset))
	}

	pw.write(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\n", numObjects))
	pw.write(fmt.Sprintf("startxref\n%d\n", xrefPos))
	pw.write("%%EOF\n")

	return nil
}
