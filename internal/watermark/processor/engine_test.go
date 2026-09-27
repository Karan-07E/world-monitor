package processor

import (
	"image"
	"image/color"
	"testing"

	"github.com/cryptoattr/secure-doc-dist/internal/watermark/payload"
)

func createTestImage(width, height int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r := byte((x * 7 + y * 13) % 256)
			g := byte((x * 11 + y * 17) % 256)
			b := byte((x * 3 + y * 19) % 256)
			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	return img
}

func TestWatermarkEmbedExtractRoundTrip(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	img := createTestImage(512, 512)

	// Create payload
	docHash := make([]byte, 32)
	sessionID := make([]byte, 32)
	watermarkID := make([]byte, 32)
	for i := range docHash {
		docHash[i] = byte(i)
	}
	for i := range sessionID {
		sessionID[i] = byte(i + 32)
	}
	for i := range watermarkID {
		watermarkID[i] = byte(i + 64)
	}

	wp, err := payload.NewPayload(docHash, sessionID, watermarkID)
	if err != nil {
		t.Fatalf("NewPayload failed: %v", err)
	}

	// Embed
	watermarked, err := engine.EmbedInImage(img, wp)
	if err != nil {
		t.Fatalf("EmbedInImage failed: %v", err)
	}

	// Extract
	result, err := engine.ExtractFromImage(watermarked)
	if err != nil {
		t.Fatalf("ExtractFromImage failed: %v", err)
	}

	if !result.Found {
		t.Fatal("watermark not found after embedding")
	}

	if !result.ChecksumValid {
		t.Fatal("checksum invalid")
	}

	if result.Payload == nil {
		t.Fatal("nil payload")
	}

	// Verify watermark ID matches
	for i := 0; i < len(watermarkID); i++ {
		if result.Payload.WatermarkID[i] != watermarkID[i] {
			t.Fatalf("watermark ID byte %d mismatch: got %d, want %d",
				i, result.Payload.WatermarkID[i], watermarkID[i])
		}
	}

	t.Logf("RS corrections: %d", result.RSCorrections)
	t.Logf("Confidence: %.4f", result.Confidence)
}

func TestDifferentWatermarkIDsProduceDifferentResults(t *testing.T) {
	engine, _ := NewEngine()

	docHash := make([]byte, 32)
	sessionID := make([]byte, 32)

	wmID1 := make([]byte, 32)
	wmID2 := make([]byte, 32)
	for i := range wmID1 {
		wmID1[i] = byte(i)
		wmID2[i] = byte(255 - i)
	}

	wp1, _ := payload.NewPayload(docHash, sessionID, wmID1)
	wp2, _ := payload.NewPayload(docHash, sessionID, wmID2)

	img := createTestImage(512, 512)

	wm1, _ := engine.EmbedInImage(img, wp1)
	wm2, _ := engine.EmbedInImage(img, wp2)

	res1, _ := engine.ExtractFromImage(wm1)
	res2, _ := engine.ExtractFromImage(wm2)

	if !res1.Found || !res2.Found {
		t.Fatal("both watermarks should be extractable")
	}

	// Watermark IDs should differ
	match := true
	for i := range res1.Payload.WatermarkID {
		if res1.Payload.WatermarkID[i] != res2.Payload.WatermarkID[i] {
			match = false
			break
		}
	}
	if match {
		t.Fatal("different watermark IDs should produce different extracted IDs")
	}
}

func TestImageTooSmall(t *testing.T) {
	engine, _ := NewEngine()

	img := createTestImage(32, 32)
	docHash := make([]byte, 32)
	sessionID := make([]byte, 32)
	watermarkID := make([]byte, 32)

	wp, _ := payload.NewPayload(docHash, sessionID, watermarkID)

	_, err := engine.EmbedInImage(img, wp)
	if err == nil {
		t.Fatal("expected error for small image")
	}
}

func TestLargerImage(t *testing.T) {
	engine, _ := NewEngine()
	img := createTestImage(1024, 768)

	docHash := make([]byte, 32)
	sessionID := make([]byte, 32)
	watermarkID := make([]byte, 32)
	for i := range watermarkID {
		watermarkID[i] = byte(i * 3)
	}

	wp, _ := payload.NewPayload(docHash, sessionID, watermarkID)

	watermarked, err := engine.EmbedInImage(img, wp)
	if err != nil {
		t.Fatalf("EmbedInImage failed: %v", err)
	}

	result, err := engine.ExtractFromImage(watermarked)
	if err != nil {
		t.Fatalf("ExtractFromImage failed: %v", err)
	}

	if !result.Found {
		t.Fatal("watermark not found in larger image")
	}
}
