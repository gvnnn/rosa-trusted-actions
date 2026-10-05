package audit

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
)

// StdoutSink writes records as JSON Lines to an io.Writer, defaulting to
// os.Stdout. It is the zero-config sink: development, and operators tailing
// container logs.
//
// Write returns nil once the write syscall returns, which means the bytes left
// this process and nothing more. A container log driver may forward them
// onward, but asynchronously and with no acknowledgement back here, so a nil
// from this sink is not a durability claim. Sound as a best-effort sink;
// listing it as required buys fail-closed control flow over a backend that
// promises nothing.
type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutSink writes to w, or to os.Stdout when w is nil. The writer is a
// parameter so tests can capture the bytes; the sink is still named "stdout"
// because that is the config spec a Name() in an error message has to point
// back at.
func NewStdoutSink(w io.Writer) *StdoutSink {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutSink{w: w}
}

func (s *StdoutSink) Name() string { return SinkStdout }

func (s *StdoutSink) Write(_ context.Context, rec Record) error {
	data, err := Encode(rec)
	if err != nil {
		return err
	}
	// One Write call, not two: a separate newline write could land between two
	// records if anything else shares the descriptor.
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.w.Write(data); err != nil {
		return fmt.Errorf("writing audit record to stdout: %w", err)
	}
	return nil
}
