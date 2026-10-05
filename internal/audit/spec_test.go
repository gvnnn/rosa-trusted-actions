package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func sinkNames(sinks []Sink) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Name())
	}
	return out
}

func assertErrContains(t *testing.T, err error, s string) {
	t.Helper()

	if !strings.Contains(err.Error(), s) {
		t.Fatalf("error %q does not mention %q", err.Error(), s)
	}
}

func TestBuildSinks_SplitsRequiredFromBestEffort(t *testing.T) {
	fileSpec := SinkFilePrefix + filepath.Join(t.TempDir(), "audit.jsonl")

	req, bestEffort, err := BuildSinks([]string{SinkStdout, fileSpec}, []string{fileSpec})
	if err != nil {
		t.Fatalf("BuildSinks failed: %v", err)
	}

	if len(req) != 1 || req[0].Name() != fileSpec {
		t.Errorf("required = %v, want exactly [%s]", sinkNames(req), fileSpec)
	}
	if len(bestEffort) != 1 || bestEffort[0].Name() != SinkStdout {
		t.Errorf("bestEffort = %v, want exactly [%s]", sinkNames(bestEffort), SinkStdout)
	}
}

func TestBuildSinks_EachInstanceAppearsExactlyOnce(t *testing.T) {
	specs := []string{SinkStdout, SinkFilePrefix + filepath.Join(t.TempDir(), "audit.jsonl")}

	req, bestEffort, err := BuildSinks(specs, []string{SinkStdout})
	if err != nil {
		t.Fatalf("BuildSinks failed: %v", err)
	}

	// Pointer identity, not Name(): this must still catch two distinct sinks
	// that happen to report the same name.
	counts := make(map[Sink]int)
	for _, s := range append(append([]Sink{}, req...), bestEffort...) {
		counts[s]++
	}

	if len(counts) != len(specs) {
		t.Fatalf("expected %d distinct sinks, got %d", len(specs), len(counts))
	}
	for sink, n := range counts {
		// A sink reachable from both slices receives every required record
		// twice, into an archive that cannot be edited afterwards.
		if n != 1 {
			t.Errorf("sink %s appears %d times across the two slices, want 1", sink.Name(), n)
		}
	}
}

func TestBuildSinks_EmptyRequiredIsRejected(t *testing.T) {
	// An Auditor with no required sinks permits every action — see
	// TestAuditor_WriteRequired_NoRequiredSinksPermitsEverything. BuildSinks is
	// the layer that refuses to build one.
	_, _, err := BuildSinks([]string{SinkStdout}, nil)
	assertErrContains(t, err, "no required audit sinks configured")
}

func TestBuildSinks_RequiredNotInSinksIsRejected(t *testing.T) {
	// Fails closed on a typo: a required sink nobody constructs would otherwise
	// leave the invariant silently unenforced.
	_, _, err := BuildSinks([]string{SinkStdout}, []string{"file:/var/log/rosa-ta/audit.jsonl"})
	assertErrContains(t, err, "required but not listed in sinks")
}

func TestBuildSinks_UnknownSpecIsRejected(t *testing.T) {
	_, _, err := BuildSinks([]string{"kafka://audit"}, []string{SinkStdout})
	assertErrContains(t, err, `unknown audit sink "kafka://audit"`)
}

func TestBuildSinks_FileSpecWithoutPathIsRejected(t *testing.T) {
	_, _, err := BuildSinks([]string{SinkFilePrefix}, []string{SinkFilePrefix})
	assertErrContains(t, err, "has no path")
}

func TestBuildSinks_DuplicateSpecIsRejected(t *testing.T) {
	_, _, err := BuildSinks([]string{SinkStdout, SinkStdout}, []string{SinkStdout})
	assertErrContains(t, err, "duplicate audit sink")
}

func TestBuildSinks_EquivalentFileSpecsAreDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// One file, two spellings. Keyed on the raw string these look distinct, and
	// two FileSinks would open the same path and double every record.
	specs := []string{SinkFilePrefix + path, SinkFilePrefix + dir + "/./audit.jsonl"}

	// required must name a sink that is in the list: otherwise this passes on
	// the "required but not listed" error and proves nothing about canonicalisation.
	_, _, err := BuildSinks(specs, []string{SinkFilePrefix + path})
	assertErrContains(t, err, "duplicate audit sink")
}

func TestBuildSinks_UnopenableFilePathPropagates(t *testing.T) {
	spec := SinkFilePrefix + filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl")

	// Construction errors surface here, at startup, rather than at the first
	// privileged action.
	_, _, err := BuildSinks([]string{spec}, []string{spec})
	assertErrContains(t, err, "opening audit file")
}
