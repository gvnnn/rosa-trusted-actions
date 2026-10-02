package audit

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// testLogger discards output: several tests exercise failure paths that log at
// Error, and the noise buries real failures.
func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// closeAuditor waits for background deliveries so assertions do not race them.
func closeAuditor(t *testing.T, a *Auditor) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

var errSinkFailed = errors.New("audit sink failed")

// memorySink collects records.
type memorySink struct {
	name    string
	mu      sync.Mutex
	records []Record
}

func (s *memorySink) Name() string { return s.name }

func (s *memorySink) Write(_ context.Context, rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

// Records returns a copy. Returning the slice itself would race with an
// in-flight background delivery under -race.
func (s *memorySink) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records)
}

// faultySink accepts the first failAfter writes, then fails permanently.
// The zero value fails on the first write, which is the fail-closed case.
type faultySink struct {
	mu        sync.Mutex
	failAfter int
	writes    int
}

func (s *faultySink) Name() string { return "faulty" }

func (s *faultySink) Write(_ context.Context, _ Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writes++; s.writes > s.failAfter {
		return errSinkFailed
	}
	return nil
}

// Writes returns the faultySink's writes attribute so that tests
// respect the Mutex and never access the field directly.
func (s *faultySink) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// flakySink fails until failUntil writes, then succeeds. The zero value
// succeeds on the first write.
type flakySink struct {
	mu        sync.Mutex
	failUntil int
	writes    int
}

func (s *flakySink) Name() string { return "flaky" }

func (s *flakySink) Write(_ context.Context, _ Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writes++; s.writes <= s.failUntil {
		return errSinkFailed
	}
	return nil
}

// Writes returns the flakySink's writes attribute so that tests
// respect the Mutex and never access the field directly.
func (s *flakySink) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

// slowSink delays each write, so Close has something in flight to wait for.
type slowSink struct {
	delay   time.Duration
	mu      sync.Mutex
	records []Record
}

func (s *slowSink) Name() string { return "slow" }

func (s *slowSink) Write(ctx context.Context, rec Record) error {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return ctx.Err()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *slowSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func TestAuditor_WriteRequired_RequiredSinkFailureBlocks(t *testing.T) {
	a := NewAuditor(testLogger(), []Sink{&faultySink{}}, nil)
	err := a.WriteRequired(context.Background(), Record{Event: EventActionAttempted})
	if err == nil {
		t.Fatal("expected an error: a failing required sink must block the action")
	}
	if !errors.Is(err, errSinkFailed) {
		t.Errorf("expected an error wrapping errSinkFailed, got %v", err)
	}
}

func TestAuditor_WriteRequired_BestEffortFailureDoesNotBlock(t *testing.T) {
	required := &memorySink{name: "required"}
	bestEffort := &memorySink{name: "best-effort"}
	faulty := &faultySink{}

	a := NewAuditor(testLogger(), []Sink{required}, []Sink{bestEffort, faulty})
	a.baseDelay = time.Millisecond

	if err := a.WriteRequired(context.Background(), Record{Event: EventActionAttempted}); err != nil {
		t.Fatalf("a best-effort failure must not fail WriteRequired: %v", err)
	}

	closeAuditor(t, a)

	if got := len(required.Records()); got != 1 {
		t.Errorf("required sink: expected 1 record, got %d", got)
	}
	if got := len(bestEffort.Records()); got != 1 {
		t.Errorf("best-effort sink: expected 1 record, got %d", got)
	}
	if got := a.Failures(); got != 1 {
		t.Errorf("expected the faulty sink to count 1 permanent failure, got %d", got)
	}
}

func TestAuditor_WriteRequired_ShortCircuitsOnFirstFailure(t *testing.T) {
	downstream := &memorySink{name: "downstream"}

	a := NewAuditor(testLogger(), []Sink{&faultySink{}, downstream}, nil)

	if err := a.WriteRequired(context.Background(), Record{Event: EventActionAttempted}); err == nil {
		t.Fatal("expected an error")
	}

	closeAuditor(t, a)

	// Short-circuiting minimises orphan attempt records: the action is blocked
	// either way, so writing the record to fewer sinks is strictly better.
	if got := len(downstream.Records()); got != 0 {
		t.Errorf("expected no write to sinks after a failing one, got %d records", got)
	}
}

func TestAuditor_WriteRequired_NoRequiredSinksPermitsEverything(t *testing.T) {
	a := NewAuditor(testLogger(), nil, nil)

	// Pins the hazard rather than endorsing it: an Auditor with no required
	// sinks silently permits every action. BuildSinks is what rejects an empty
	// required list; the Auditor itself does not.
	if err := a.WriteRequired(context.Background(), Record{Event: EventActionAttempted}); err != nil {
		t.Errorf("expected nil with no required sinks, got %v", err)
	}
}

func TestAuditor_Deliver_WritesToAllSinks(t *testing.T) {
	required := &memorySink{name: "required"}
	bestEffort := &memorySink{name: "best-effort"}

	a := NewAuditor(testLogger(), []Sink{required}, []Sink{bestEffort})

	a.Deliver(Record{Event: EventActionCompleted})
	closeAuditor(t, a)

	// The required/best-effort split governs WriteRequired only. By the time
	// Deliver runs, the side effect has already happened — nothing left to gate.
	if got := len(required.Records()); got != 1 {
		t.Errorf("required sink: expected 1 record, got %d", got)
	}
	if got := len(bestEffort.Records()); got != 1 {
		t.Errorf("best-effort sink: expected 1 record, got %d", got)
	}
}

func TestAuditor_Deliver_SequenceIsGapless(t *testing.T) {
	const writers = 50

	sink := &memorySink{name: "memory"}
	a := NewAuditor(testLogger(), []Sink{sink}, nil)

	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Deliver(Record{Event: EventActionCompleted})
		}()
	}
	wg.Wait()

	closeAuditor(t, a)

	records := sink.Records()
	if len(records) != writers {
		t.Fatalf("expected %d records, got %d", writers, len(records))
	}

	seqs := make([]uint64, 0, len(records))
	for _, rec := range records {
		seqs = append(seqs, rec.Sequence)
	}
	slices.Sort(seqs)

	// Monotonicity is not the property that matters. Downstream reads a gap as
	// proof of loss, which only holds if nothing is ever skipped.
	for i, got := range seqs {
		if want := uint64(i + 1); got != want {
			t.Fatalf("sequence[%d] = %d, want %d — a gap here means a lost record", i, got, want)
		}
	}
}

func TestAuditor_Deliver_RetriesThenCountsFailure(t *testing.T) {
	faulty := &faultySink{}

	a := NewAuditor(testLogger(), nil, []Sink{faulty})
	a.baseDelay = time.Millisecond

	a.Deliver(Record{Event: EventActionCompleted})
	closeAuditor(t, a)

	if got := faulty.Writes(); got != a.maxAttempts {
		t.Errorf("expected %d write attempts, got %d", a.maxAttempts, got)
	}
	if got := a.Failures(); got != 1 {
		t.Errorf("expected Failures() == 1, got %d", got)
	}
}

func TestAuditor_Deliver_SucceedsAfterRetry(t *testing.T) {
	flaky := &flakySink{failUntil: 2}

	a := NewAuditor(testLogger(), nil, []Sink{flaky})
	a.baseDelay = time.Millisecond

	a.Deliver(Record{Event: EventActionCompleted})
	closeAuditor(t, a)

	if got := flaky.Writes(); got != 3 {
		t.Errorf("expected 3 attempts (2 failures then success), got %d", got)
	}
	if got := a.Failures(); got != 0 {
		t.Errorf("a record delivered on retry must not count as a failure, got %d", got)
	}
}

func TestAuditor_Close_FlushesInFlightDeliveries(t *testing.T) {
	sink := &slowSink{delay: 50 * time.Millisecond}
	a := NewAuditor(testLogger(), nil, []Sink{sink})

	a.Deliver(Record{Event: EventActionCompleted})
	closeAuditor(t, a)

	if got := sink.Count(); got != 1 {
		t.Errorf("expected Close to wait for the in-flight delivery, got %d records", got)
	}
}

func TestAuditor_Close_ReturnsErrorWhenDeliveriesOutlastContext(t *testing.T) {
	a := NewAuditor(testLogger(), nil, []Sink{&slowSink{delay: 200 * time.Millisecond}})

	a.Deliver(Record{Event: EventActionCompleted})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := a.Close(ctx)
	if err == nil {
		t.Fatal("expected Close to report deliveries still in flight")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected a wrapped context error, got %v", err)
	}
}

func TestAuditor_Stamp_PreservesPresetID(t *testing.T) {
	const preset = "aaaaaaaa-0000-4000-8000-000000000001"

	a := NewAuditor(testLogger(), nil, nil)

	if got := a.stamp(Record{ID: preset}).ID; got != preset {
		t.Errorf("expected the preset ID to survive stamping, got %q", got)
	}

	generated := a.stamp(Record{}).ID
	if generated == "" {
		t.Error("expected an ID to be generated when empty")
	}
	if generated == preset {
		t.Error("expected a distinct generated ID")
	}
}

func TestAuditor_Stamp_NormalisesTimestampToUTC(t *testing.T) {
	a := NewAuditor(testLogger(), nil, nil)

	if got := a.stamp(Record{}).Timestamp.Location(); got != time.UTC {
		t.Errorf("generated timestamp: location %v, want UTC", got)
	}

	offset := time.Date(2026, 1, 15, 9, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	stamped := a.stamp(Record{Timestamp: offset}).Timestamp

	if got := stamped.Location(); got != time.UTC {
		t.Errorf("caller-supplied timestamp: location %v, want UTC", got)
	}
	if got := stamped.Hour(); got != 7 {
		t.Errorf("expected 09:30+02:00 to normalise to 07:30Z, got hour %d", got)
	}
	// Normalising the representation must not move the instant.
	if !stamped.Equal(offset) {
		t.Errorf("stamped %v is a different instant from %v", stamped, offset)
	}
}
