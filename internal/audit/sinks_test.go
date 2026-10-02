package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// decodeLines splits JSON Lines output and decodes every line, failing on any
// line that is not a complete record. A sink that interleaves two records
// produces unparseable lines, so this is also the interleaving assertion.
func decodeLines(t *testing.T, data []byte) []Record {
	t.Helper()

	if len(data) == 0 {
		return nil
	}

	if data[len(data)-1] != '\n' {
		t.Fatalf("expected output to end with a newline, got %q", data)
	}

	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	records := make([]Record, 0, len(lines))
	for i, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d is not a complete record: %v\n%s", i, err, line)
		}
		records = append(records, rec)
	}
	return records
}

// readRecords reads a file sink's output and decodes it. filepath.Clean is
// what keeps gosec's G304 quiet without a nolint directive.
func readRecords(t *testing.T, path string) []Record {
	t.Helper()

	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit file: %v", err)
	}

	return decodeLines(t, data)
}

func TestStdoutSink_WritesOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)

	for i := range 2 {
		rec := Record{Event: EventActionCompleted, ID: fmt.Sprintf("rec-%d", i)}
		if err := sink.Write(context.Background(), rec); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	records := decodeLines(t, buf.Bytes())
	if len(records) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(records))
	}
	for i, r := range records {
		if want := fmt.Sprintf("rec-%d", i); r.ID != want {
			t.Errorf("line %d: ID = %q, want %q", i, r.ID, want)
		}
	}
}

func TestStdoutSink_ConcurrentWritesDoNotInterleave(t *testing.T) {
	const writers = 50

	var buf bytes.Buffer
	sink := NewStdoutSink(&buf)

	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := Record{Event: EventActionCompleted, ID: fmt.Sprintf("rec-%d", i)}
			if err := sink.Write(context.Background(), rec); err != nil {
				t.Errorf("Write failed: %v", err)
			}
		}()
	}
	wg.Wait()

	// bytes.Buffer is not concurrency-safe: without the sink's mutex this both
	// races and shreds the output.
	if got := len(decodeLines(t, buf.Bytes())); got != writers {
		t.Errorf("expected %d intact lines, got %d", writers, got)
	}
}

func TestStdoutSink_Name(t *testing.T) {
	if got := NewStdoutSink(nil).Name(); got != "stdout" {
		t.Errorf("Name() = %q, want %q — it must match the config spec", got, "stdout")
	}
}

func TestFileSink_AppendsAcrossWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}

	for i := range 2 {
		rec := Record{Event: EventActionCompleted, ID: fmt.Sprintf("rec-%d", i)}
		if err := sink.Write(context.Background(), rec); err != nil {
			t.Fatalf("Write failed: %v", err)
		}
	}

	if got := len(readRecords(t, path)); got != 2 {
		t.Errorf("expected 2 lines, got %d", got)
	}
}

func TestFileSink_DoesNotTruncateExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	first, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}
	if err := first.Write(context.Background(), Record{ID: "before-restart"}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// A second sink on the same path stands in for a process restart. Opening
	// with O_TRUNC here would silently destroy the existing audit trail.
	second, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("reopening sink failed: %v", err)
	}
	if err := second.Write(context.Background(), Record{ID: "after-restart"}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	records := readRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("expected 2 records to survive the reopen, got %d", len(records))
	}
	if records[0].ID != "before-restart" {
		t.Errorf("records[0].ID = %q, want %q", records[0].ID, "before-restart")
	}
}

func TestFileSink_UnopenablePathFailsAtConstruction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")

	if _, err := NewFileSink(path); err == nil {
		t.Fatal("expected an error: a bad audit path must fail at startup, not at the first action")
	}
}

func TestFileSink_Name(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}
	if want := "file:" + path; sink.Name() != want {
		t.Errorf("Name() = %q, want %q — BuildSinks errors quote this back at the operator", sink.Name(), want)
	}
}

func TestFileSink_PermissionsAreOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	if _, err := NewFileSink(path); err != nil {
		t.Fatalf("NewFileSink failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	// The file holds caller identities and cluster identifiers.
	if got := info.Mode().Perm(); got != auditFileMode {
		t.Errorf("mode = %04o, want %04o", got, auditFileMode)
	}
}
