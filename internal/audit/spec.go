package audit

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// SinkStdout is the config spec selecting a StdoutSink.
	SinkStdout = "stdout"
	// SinkFilePrefix introduces a FileSink spec: "file:/var/log/rosa-ta/audit.jsonl".
	SinkFilePrefix = "file:"
)

// BuildSinks turns config specs into sinks, split into the ones that must
// accept a record before a privileged action may run and the ones delivered in
// the background.
//
// Every spec is constructed exactly once and lands in exactly one slice. A
// sink reachable from both would receive each required record twice, and a
// duplicate in an archive that cannot be edited is not something a later pass
// can clean up.
func BuildSinks(sinks, required []string) (req, bestEffort []Sink, err error) {
	if len(required) == 0 {
		return nil, nil, fmt.Errorf(
			"no required audit sinks configured: at least one sink must confirm a record before a privileged action may run")
	}

	isRequired := make(map[string]bool, len(required))
	for _, spec := range required {
		isRequired[canonicalSpec(spec)] = true
	}

	seen := make(map[string]bool, len(sinks))
	for _, spec := range sinks {
		key := canonicalSpec(spec)
		if seen[key] {
			return nil, nil, fmt.Errorf("duplicate audit sink %q: every record would be written to it twice", key)
		}
		seen[key] = true

		sink, buildErr := newSink(spec)
		if buildErr != nil {
			return nil, nil, buildErr
		}

		if isRequired[key] {
			req = append(req, sink)
		} else {
			bestEffort = append(bestEffort, sink)
		}
	}

	for _, spec := range required {
		if !seen[canonicalSpec(spec)] {
			return nil, nil, fmt.Errorf("audit sink %q is required but not listed in sinks", spec)
		}
	}

	return req, bestEffort, nil
}

// canonicalSpec normalises a spec so two spellings of one destination collide:
// "file:./audit.jsonl" and "file:audit.jsonl" are the same file, and opening
// it twice would double every record.
func canonicalSpec(spec string) string {
	if path, ok := strings.CutPrefix(spec, SinkFilePrefix); ok && spec != "" {
		return SinkFilePrefix + filepath.Clean(path)
	}
	return spec
}

func newSink(spec string) (Sink, error) {
	switch {
	case spec == SinkStdout:
		return NewStdoutSink(nil), nil
	case strings.HasPrefix(spec, SinkFilePrefix):
		path := strings.TrimPrefix(spec, SinkFilePrefix)
		if path == "" {
			return nil, fmt.Errorf("audit sink %q has no path", spec)
		}
		return NewFileSink(path)
	default:
		return nil, fmt.Errorf("unknown audit sink %q: want %q or %q<path>", spec, SinkStdout, SinkFilePrefix)
	}
}
