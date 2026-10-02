package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Encode renders a record as canonical JSON: a single line, no trailing
// newline, fields in struct declaration order. Every sink ships these exact
// bytes so a record is byte-identical wherever it lands.
func Encode(rec Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, fmt.Errorf("encoding audit record: %w", err)
	}

	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
