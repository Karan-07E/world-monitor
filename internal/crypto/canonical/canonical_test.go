package canonical

import (
	"bytes"
	"testing"
)

type testRecord struct {
	Zebra string `json:"zebra"`
	Alpha string `json:"alpha"`
	Mid   int    `json:"mid"`
}

func TestDeterministicSerialization(t *testing.T) {
	r := testRecord{Zebra: "last", Alpha: "first", Mid: 42}

	out1, err := Serialize(r)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	out2, err := Serialize(r)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if !bytes.Equal(out1, out2) {
		t.Fatalf("serialization not deterministic:\n%s\nvs\n%s", string(out1), string(out2))
	}
}

func TestSortedKeys(t *testing.T) {
	r := testRecord{Zebra: "z", Alpha: "a", Mid: 1}

	out, _ := Serialize(r)
	s := string(out)

	// alpha should come before mid, mid before zebra
	alphaIdx := bytes.Index(out, []byte(`"alpha"`))
	midIdx := bytes.Index(out, []byte(`"mid"`))
	zebraIdx := bytes.Index(out, []byte(`"zebra"`))

	if alphaIdx >= midIdx || midIdx >= zebraIdx {
		t.Fatalf("keys not sorted: %s", s)
	}
}

func TestSerializeAndHash(t *testing.T) {
	r := testRecord{Zebra: "z", Alpha: "a", Mid: 1}

	h1, err := SerializeAndHash(r)
	if err != nil {
		t.Fatalf("SerializeAndHash failed: %v", err)
	}
	if len(h1) != 32 {
		t.Fatalf("hash length = %d, want 32", len(h1))
	}

	// Same input = same hash
	h2, _ := SerializeAndHash(r)
	if !bytes.Equal(h1, h2) {
		t.Fatal("hash not deterministic")
	}

	// Different input = different hash
	r2 := testRecord{Zebra: "z", Alpha: "b", Mid: 1}
	h3, _ := SerializeAndHash(r2)
	if bytes.Equal(h1, h3) {
		t.Fatal("different inputs produced same hash")
	}
}

func TestNestedStruct(t *testing.T) {
	type Inner struct {
		B string `json:"b"`
		A string `json:"a"`
	}
	type Outer struct {
		Y     Inner  `json:"y"`
		X     string `json:"x"`
	}

	o := Outer{Y: Inner{B: "2", A: "1"}, X: "hello"}

	out1, _ := Serialize(o)
	out2, _ := Serialize(o)

	if !bytes.Equal(out1, out2) {
		t.Fatal("nested serialization not deterministic")
	}

	// Verify key ordering
	s := string(out1)
	xIdx := bytes.Index(out1, []byte(`"x"`))
	yIdx := bytes.Index(out1, []byte(`"y"`))
	if xIdx >= yIdx {
		t.Fatalf("keys not sorted in nested: %s", s)
	}
}
