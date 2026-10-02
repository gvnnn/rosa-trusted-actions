package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// auditFileMode keeps the audit file readable only by the process owner: it
// holds caller identities and cluster identifiers.
const auditFileMode = 0o600

// FileSink appends records as JSON Lines to a file, syncing after each write.
type FileSink struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// NewFileSink opens path for appending, creating it if absent. Opening at
// construction rather than lazily means a bad path fails at startup instead of
// at the first privileged action — the one moment the audit trail must not be
// discovering problems.
func NewFileSink(path string) (*FileSink, error) {
	path = filepath.Clean(path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, auditFileMode)
	if err != nil {
		return nil, fmt.Errorf("opening audit file %s: %w", path, err)
	}

	return &FileSink{path: path, f: f}, nil
}

func (s *FileSink) Name() string { return "file:" + s.path }

func (s *FileSink) Write(_ context.Context, rec Record) error {
	data, err := Encode(rec)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.f.Write(data); err != nil {
		return fmt.Errorf("writing audit record to %s: %w", s.path, err)
	}
	// Without the sync, nil would mean "the kernel has the bytes", which a
	// crash or host failure can still lose. A required sink's nil is what
	// permits a privileged action, so it has to mean durable.
	if err = s.f.Sync(); err != nil {
		return fmt.Errorf("syncing audit file %s: %w", s.path, err)
	}
	return nil
}
