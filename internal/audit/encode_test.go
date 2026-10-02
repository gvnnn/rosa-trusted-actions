package audit

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
)

const goldenPath = "testdata/record.golden.json"

var update = flag.Bool("update", false, "rewrite golden files")

// goldenRecord is deliberately synthetic: every field is populated, including
// combinations that never occur together in practice (a deny reason on a
// completed action), so the golden file pins a complete wire format.
// TestEncode_OmitsEmpty covers a realistic minimal record.
func goldenRecord() Record {
	return Record{
		ID:        "aaaaaaaa-0000-4000-8000-000000000001",
		Sequence:  42,
		Timestamp: time.Date(2026, 1, 15, 9, 30, 0, 123456789, time.UTC),
		Event:     EventActionCompleted,
		CallerID:  "test-user@example.com",
		Action:    "get",
		Target: actions.ResourceTarget{
			Version:   "v1",
			Resource:  "configmaps",
			Namespace: "test-namespace",
			Name:      "test-configmap",
		},
		ClusterID:  "cccccccc-0000-4000-8000-000000000002",
		Decision:   DecisionAllowed,
		DenyReason: "namespace not in allow-list",
		Outcome:    OutcomeFailure,
		// Contains & and > to pin the SetEscapeHTML(false) decision.
		Error:       `resource "a&b" not found: scope > allowed`,
		ExecutionID: "eeeeeeee-0000-4000-8000-000000000003",
		RequestID:   "0000000000000001",
	}
}

func TestEncode_Golden(t *testing.T) {
	got, err := Encode(goldenRecord())
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if *update {
		if err := os.WriteFile(goldenPath, append(got, '\n'), 0o600); err != nil {
			t.Fatalf("updating golden file: %v", err)
		}
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}

	// pre-commit's end-of-file-fixer appends a newline to the golden file,
	// but Encode never emits one — sinks add their own framing.
	want = bytes.TrimRight(want, "\n")

	if !bytes.Equal(got, want) {
		t.Errorf("encoded record does not match %s\n got: %s\nwant: %s", goldenPath, got, want)
	}
}

func TestEncode_OmitsEmpty(t *testing.T) {
	// A realistic action.attempted record: authorized, not yet executed.
	rec := Record{
		ID:        "aaaaaaaa-0000-4000-8000-000000000001",
		Sequence:  42,
		Timestamp: time.Date(2026, 1, 15, 9, 30, 0, 123456789, time.UTC),
		Event:     EventActionAttempted,
		CallerID:  "test-user@example.com",
		Action:    "get",
		Target: actions.ResourceTarget{
			Version:   "v1",
			Resource:  "configmaps",
			Namespace: "test-namespace",
			Name:      "test-configmap",
		},
		ClusterID: "cccccccc-0000-4000-8000-000000000002",
		Decision:  DecisionAllowed,
	}

	data, err := Encode(rec)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshalling encoded record: %v", err)
	}

	for _, key := range []string{"deny_reason", "outcome", "error", "execution_id", "request_id"} {
		if _, ok := fields[key]; ok {
			t.Errorf("expected %q to be omitted from a minimal record, got %s", key, fields[key])
		}
	}
	for _, key := range []string{
		"id", "sequence", "timestamp", "event",
		"caller_id", "action", "target", "cluster_id", "decision",
	} {
		if _, ok := fields[key]; !ok {
			t.Errorf("expected %q to be present", key)
		}
	}
}

func TestEncode_DoesNotEscapeHTML(t *testing.T) {
	data, err := Encode(Record{Error: `a & b > c <`})
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	for _, escaped := range []string{`\u0026`, `\u003e`, `\u003c`} {
		if bytes.Contains(data, []byte(escaped)) {
			t.Errorf("expected HTML escaping to be disabled, found %s in: %s", escaped, data)
		}
	}
}
