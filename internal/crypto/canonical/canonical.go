// Package canonical provides deterministic canonical serialization for signing.
package canonical

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// Serialize produces a deterministic canonical JSON serialization of a struct.
// This ensures consistent byte sequences for signature generation and verification.
// Uses sorted keys and no whitespace.
func Serialize(v interface{}) ([]byte, error) {
	// First marshal to get raw JSON
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshaling for canonical form: %w", err)
	}

	// Unmarshal into an interface{} to normalize
	var normalized interface{}
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, fmt.Errorf("normalizing JSON: %w", err)
	}

	// Re-serialize with sorted keys
	canonical, err := canonicalMarshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonical marshal: %w", err)
	}

	return canonical, nil
}

// SerializeAndHash produces the SHA-256 hash of canonical serialization.
func SerializeAndHash(v interface{}) ([]byte, error) {
	canonical, err := Serialize(v)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(canonical)
	return hash[:], nil
}

// canonicalMarshal recursively serializes a value with sorted map keys.
func canonicalMarshal(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return canonicalMarshalMap(val)
	case []interface{}:
		return canonicalMarshalArray(val)
	default:
		return json.Marshal(v)
	}
}

func canonicalMarshalMap(m map[string]interface{}) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := []byte("{")
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')

		valBytes, err := canonicalMarshal(m[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func canonicalMarshalArray(arr []interface{}) ([]byte, error) {
	buf := []byte("[")
	for i, elem := range arr {
		if i > 0 {
			buf = append(buf, ',')
		}
		elemBytes, err := canonicalMarshal(elem)
		if err != nil {
			return nil, err
		}
		buf = append(buf, elemBytes...)
	}
	buf = append(buf, ']')
	return buf, nil
}
