package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	defaultMaxAttempts = 3
	defaultBaseDelay   = 100 * time.Millisecond
	// deliveryTimeout bounds a single background write attempt.
	deliveryTimeout = 10 * time.Second
)

type Auditor struct {
	logger      *logrus.Logger
	required    []Sink
	bestEffort  []Sink
	seq         atomic.Uint64
	failures    atomic.Uint64
	wg          sync.WaitGroup
	maxAttempts int
	baseDelay   time.Duration
}

func NewAuditor(logger *logrus.Logger, required, bestEffort []Sink) *Auditor {
	return &Auditor{
		logger:      logger,
		required:    required,
		bestEffort:  bestEffort,
		maxAttempts: defaultMaxAttempts,
		baseDelay:   defaultBaseDelay,
	}
}

// Deliver records something that already happened. It never blocks the caller
// and never fails the operation: delivery is retried with backoff in the
// background, and exhaustion logs at Error and increments the failure counter.
//
// ctx is used for its values only — deliverAsync strips cancellation and the
// deadline, so a request context being cancelled when the response is written
// does not abort the delivery.
func (a *Auditor) Deliver(ctx context.Context, rec Record) {
	rec = a.stamp(rec)
	a.deliverAsync(ctx, rec, a.required)
	a.deliverAsync(ctx, rec, a.bestEffort)
}

// WriteRequired writes rec to every required sink synchronously and returns
// the first error. A non-nil return means the caller MUST NOT perform the side
// effect the record describes. Best-effort sinks are attempted but cannot
// cause a non-nil return.
func (a *Auditor) WriteRequired(ctx context.Context, rec Record) error {
	rec = a.stamp(rec)
	for _, sink := range a.required {
		if err := sink.Write(ctx, rec); err != nil {
			a.logger.WithFields(logrus.Fields{
				"sink":     sink.Name(),
				"event":    rec.Event,
				"record":   rec.ID,
				"sequence": rec.Sequence,
			}).WithError(err).Error("Required audit sink failed; action must not proceed")
			return fmt.Errorf("required audit sink %s: %w", sink.Name(), err)
		}
	}

	a.deliverAsync(ctx, rec, a.bestEffort)
	return nil
}

// stamp fills the identity fields that make a record traceable. ID is
// preserved if the caller pre-set it, so a caller that built the record
// earlier can correlate it. Sequence is always assigned: it is the Auditor's
// own counter, and a gap in it is the only evidence of loss. The counter
// starts at 1, leaving 0 as an unambiguous "never stamped".
func (a *Auditor) stamp(rec Record) Record {
	if rec.ID == "" {
		rec.ID = uuid.NewString()
	}
	rec.Sequence = a.seq.Add(1)
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	} else {
		// Normalise: a caller-supplied local timestamp would encode with an
		// offset, making archive ordering depend on where the process ran.
		rec.Timestamp = rec.Timestamp.UTC()
	}
	return rec
}

// deliverAsync fans rec out to sinks in the background. The parent context is
// stripped of cancellation and deadline: a request context is cancelled the
// moment the response is written, which would abort the very delivery the
// retry loop exists to complete. Values (request ID, trace span) survive.
func (a *Auditor) deliverAsync(ctx context.Context, rec Record, sinks []Sink) {
	parent := context.WithoutCancel(ctx)
	for _, sink := range sinks {
		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.writeWithRetry(parent, rec, sink)
		}()
	}
}

func (a *Auditor) writeWithRetry(parent context.Context, rec Record, sink Sink) {
	delay := a.baseDelay

	for attempt := 1; attempt <= a.maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(parent, deliveryTimeout)
		err := sink.Write(ctx, rec)
		cancel()

		if err == nil {
			return
		}

		if attempt < a.maxAttempts {
			time.Sleep(delay)
			delay *= 2
			continue
		}

		a.failures.Add(1)
		a.logger.WithFields(logrus.Fields{
			"sink":     sink.Name(),
			"event":    rec.Event,
			"record":   rec.ID,
			"sequence": rec.Sequence,
			"attempts": a.maxAttempts,
		}).WithError(err).Error("Audit record not delivered, permanently skipped")
	}
}

// Close waits for in-flight background deliveries, bounded by ctx.
func (a *Auditor) Close(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit deliveries still in flight at shutdown: %w", ctx.Err())
	}
}

// Failures reports permanently-undelivered records, for /health and metrics.
func (a *Auditor) Failures() uint64 { return a.failures.Load() }
