package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
	"github.com/openshift-online/rosa-trusted-actions/internal/audit"
	"github.com/openshift-online/rosa-trusted-actions/internal/authorization"
	"github.com/openshift-online/rosa-trusted-actions/internal/backplane"
	"k8s.io/client-go/dynamic"
)

var errSinkDown = errors.New("sink down")

type fakeClientProvider struct {
	client dynamic.Interface
	err    error
	mu     sync.Mutex
	calls  int
}

func (f *fakeClientProvider) GetClient(_ context.Context, _ string, _ []backplane.RBACRule) (dynamic.Interface, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

func (f *fakeClientProvider) GetPodExecutor(_ context.Context, _ string, _ []backplane.RBACRule) (backplane.PodExecutor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	return nil, fmt.Errorf("not implemented in test fake")
}

func (f *fakeClientProvider) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// auditSpy is an Auditor wired to a recording sink. Deliver is asynchronous,
// so records() flushes before returning - reading the sink directly races the
// delivery goroutine and fails under -race.
type auditSpy struct {
	*audit.Auditor
	sink *recordingSink
}

func (s *auditSpy) records(t *testing.T) []audit.Record {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Close(ctx); err != nil {
		t.Fatalf("flushing auditor: %v", err)
	}

	return s.sink.Records()
}

// recordingSink collects records.
type recordingSink struct {
	name    string
	mu      sync.Mutex
	records []audit.Record
}

func (s *recordingSink) Name() string { return s.name }

func (s *recordingSink) Write(_ context.Context, rec audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

// Records returns a copy. Returning the slice itself would race with
// an in-flight background delivery under -race.
func (s *recordingSink) Records() []audit.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.records)
}

type failingSink struct{}

func (s *failingSink) Name() string { return "failing" }

func (s *failingSink) Write(_ context.Context, rec audit.Record) error { return errSinkDown }

func newTestExecutor(namespaces, secrets []string, bp backplane.ClientProvider) (*Executor, *auditSpy) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	sink := &recordingSink{name: "recording"}
	auditor := audit.NewAuditor(logger, []audit.Sink{sink}, nil)
	authz := authorization.New(logger, namespaces, secrets)
	return New(logger, authz, auditor, bp), &auditSpy{auditor, sink}
}

func newFakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), objects...)
}

func newConfigMap(namespace, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"namespace": namespace,
				"name":      name,
			},
		},
	}
}

var testTarget = actions.ResourceTarget{
	Group:     "",
	Version:   "v1",
	Resource:  "configmaps",
	Namespace: "openshift-monitoring",
	Name:      "cluster-config",
}

func TestExecutor_HappyPath_Get(t *testing.T) {
	cm := newConfigMap("openshift-monitoring", "cluster-config")
	bp := &fakeClientProvider{client: newFakeClient(cm)}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    testTarget,
	})

	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}

	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}

	if result.Output == nil {
		t.Fatal("expected output, got nil")
	}

	if len(result.Output.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(result.Output.Resources))
	}

	records := auditor.records(t)

	if len(records) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(records))
	}

	byEvent := recordsByEvent(t, records)
	if byEvent[audit.EventActionAttempted].Decision != audit.DecisionAllowed {
		t.Errorf("expected audit decision %q, got %q",
			audit.DecisionAllowed, byEvent[audit.EventActionAttempted].Decision)
	}
	if byEvent[audit.EventActionCompleted].Outcome != audit.OutcomeSuccess {
		t.Errorf("expected audit outcome %q, got %q",
			audit.OutcomeSuccess, byEvent[audit.EventActionCompleted].Outcome)
	}
}

func TestExecutor_DeniedNamespace(t *testing.T) {
	bp := &fakeClientProvider{client: newFakeClient()}
	exec, auditor := newTestExecutor([]string{"openshift-logging"}, nil, bp)

	target := testTarget
	target.Namespace = "customer-namespace"

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    target,
	})

	if result.Allowed {
		t.Error("expected denied, got allowed")
	}

	records := auditor.records(t)

	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Event != audit.EventActionDenied {
		t.Errorf("expected event %q, got %q", audit.EventActionDenied, records[0].Event)
	}
	if records[0].Decision != audit.DecisionDenied {
		t.Errorf("expected audit decision %q, got %q", audit.DecisionDenied, records[0].Decision)
	}
	if records[0].Outcome != audit.OutcomeSkipped {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeSkipped, records[0].Outcome)
	}
}

func TestExecutor_DeniedSecret(t *testing.T) {
	bp := &fakeClientProvider{client: newFakeClient()}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	target := actions.ResourceTarget{
		Group:     "",
		Version:   "v1",
		Resource:  "secrets",
		Namespace: "openshift-monitoring",
		Name:      "some-secret",
	}

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    target,
	})

	records := auditor.records(t)

	if result.Allowed {
		t.Error("expected secret to be denied, got allowed")
	}
	// A denial never reaches WriteRequired, so there is no action.attempted.
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Event != audit.EventActionDenied {
		t.Errorf("expected event %q, got %q", audit.EventActionDenied, records[0].Event)
	}
	if records[0].Decision != audit.DecisionDenied {
		t.Errorf("expected audit decision %q, got %q", audit.DecisionDenied, records[0].Decision)
	}
}

func TestExecutor_AllowedSecret(t *testing.T) {
	secret := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"namespace": "openshift-monitoring",
				"name":      "alertmanager-config",
			},
		},
	}
	bp := &fakeClientProvider{client: newFakeClient(secret)}
	exec, auditor := newTestExecutor(
		[]string{"openshift-monitoring"},
		[]string{"openshift-monitoring/alertmanager-config"},
		bp,
	)

	target := actions.ResourceTarget{
		Group:     "",
		Version:   "v1",
		Resource:  "secrets",
		Namespace: "openshift-monitoring",
		Name:      "alertmanager-config",
	}

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    target,
	})

	records := auditor.records(t)

	if !result.Allowed {
		t.Errorf("expected allowed for allow-listed secret, got denied: %s", result.Reason)
	}
	if result.Error != nil {
		t.Errorf("unexpected error: %v", result.Error)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(records))
	}
	if records[0].Decision != audit.DecisionAllowed {
		t.Errorf("expected audit decision %q, got %q", audit.DecisionAllowed, records[0].Decision)
	}
}

func TestExecutor_BackplaneError(t *testing.T) {
	bp := &fakeClientProvider{err: fmt.Errorf("backplane unavailable")}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    testTarget,
	})

	records := auditor.records(t)

	if !result.Allowed {
		t.Error("expected allowed (auth passed), got denied")
	}
	if result.Error == nil {
		t.Error("expected error from backplane failure, got nil")
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(records))
	}

	byEvent := recordsByEvent(t, records)
	// The attempt was written before the backplane was reached — that write
	// succeeding is what permitted the call that then failed.
	if _, ok := byEvent[audit.EventActionAttempted]; !ok {
		t.Errorf("no %q record", audit.EventActionAttempted)
	}
	if got := byEvent[audit.EventActionCompleted].Outcome; got != audit.OutcomeFailure {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeFailure, got)
	}
}

func TestExecutor_ActionError(t *testing.T) {
	bp := &fakeClientProvider{client: newFakeClient()}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	target := testTarget
	target.Name = "nonexistent"

	result := exec.Execute(context.Background(), Request{
		CallerID:  "test-user",
		ClusterID: "cluster-123",
		Action:    actions.NewGetAction(),
		Target:    target,
	})

	records := auditor.records(t)

	if !result.Allowed {
		t.Error("expected allowed (auth passed), got denied")
	}
	if result.Error == nil {
		t.Error("expected error from action failure, got nil")
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(records))
	}

	byEvent := recordsByEvent(t, records)
	if got := byEvent[audit.EventActionCompleted].Outcome; got != audit.OutcomeFailure {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeFailure, got)
	}
}

func TestExecutor_AuditRecordFields(t *testing.T) {
	cm := newConfigMap("openshift-monitoring", "cluster-config")
	bp := &fakeClientProvider{client: newFakeClient(cm)}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	exec.Execute(context.Background(), Request{
		CallerID:  "srep-user",
		ClusterID: "cluster-456",
		Action:    actions.NewGetAction(),
		Target:    testTarget,
	})

	records := auditor.records(t)

	if len(records) != 2 {
		t.Fatalf("expected 2 audit records, got %d", len(records))
	}

	// Every identifying field must be present on both records: an
	// action.attempted found without its completion has to be self-describing.
	for _, rec := range records {
		if rec.CallerID != "srep-user" {
			t.Errorf("%s: expected caller %q, got %q", rec.Event, "srep-user", rec.CallerID)
		}
		if rec.ClusterID != "cluster-456" {
			t.Errorf("%s: expected cluster %q, got %q", rec.Event, "cluster-456", rec.ClusterID)
		}
		if rec.Action != "get" {
			t.Errorf("%s: expected action %q, got %q", rec.Event, "get", rec.Action)
		}
		if rec.Target.Resource != "configmaps" {
			t.Errorf("%s: expected resource type %q, got %q", rec.Event, "configmaps", rec.Target.Resource)
		}
		if rec.Target.Namespace != "openshift-monitoring" {
			t.Errorf("%s: expected namespace %q, got %q", rec.Event, "openshift-monitoring", rec.Target.Namespace)
		}
		if rec.Target.Name != "cluster-config" {
			t.Errorf("%s: expected name %q, got %q", rec.Event, "cluster-config", rec.Target.Name)
		}
	}
}

func TestExecutor_AuditFailurePreventsExecution(t *testing.T) {
	cm := newConfigMap("openshift-monitoring", "cluster-config")
	bp := &fakeClientProvider{client: newFakeClient(cm)}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	auditor := audit.NewAuditor(logger, []audit.Sink{&failingSink{}}, nil)
	authz := authorization.New(logger, []string{"openshift-monitoring"}, nil)
	exec := New(logger, authz, auditor, bp)

	result := exec.Execute(context.Background(), Request{
		ExecutionID: "exec-1",
		CallerID:    "test-user",
		ClusterID:   "cluster-123",
		Action:      actions.NewGetAction(),
		Target:      testTarget,
	})

	if !errors.Is(result.Error, ErrAuditUnavailable) {
		t.Fatalf("expected ErrAuditUnavailable, got %v", result.Error)
	}
	// Authorization permitted this; the audit layer refused it. Reporting
	// Allowed=false would misattribute the failure to the caller.
	if !result.Allowed {
		t.Error("expected Allowed=true: authorization passed, audit blocked")
	}
	// The entire invariant, in one assertion: no backplane grant was
	// requested, so no privileged side effect occurred.
	if got := bp.Calls(); got != 0 {
		t.Errorf("backplane was called %d times; a failed required audit write must prevent every side effect", got)
	}
}

// recordsByEvent indexes a flushed record set by its event discriminator,
// failing on a duplicate: every assertion below depends on there being at most
// one record per event for a single execution.
func recordsByEvent(t *testing.T, records []audit.Record) map[audit.Event]audit.Record {
	t.Helper()

	byEvent := make(map[audit.Event]audit.Record, len(records))
	for _, rec := range records {
		if _, dup := byEvent[rec.Event]; dup {
			t.Fatalf("two %q records for one execution", rec.Event)
		}
		byEvent[rec.Event] = rec
	}
	return byEvent
}

func TestExecutor_BestEffortFailureDoesNotFailAction(t *testing.T) {
	cm := newConfigMap("openshift-monitoring", "cluster-config")
	bp := &fakeClientProvider{client: newFakeClient(cm)}

	logger := logrus.New()
	logger.SetOutput(io.Discard)
	sink := &recordingSink{name: "recording"}
	auditor := audit.NewAuditor(logger, []audit.Sink{sink}, []audit.Sink{&failingSink{}})
	authz := authorization.New(logger, []string{"openshift-monitoring"}, nil)
	exec := New(logger, authz, auditor, bp)

	result := exec.Execute(context.Background(), Request{
		ExecutionID: "exec-best-effort",
		CallerID:    "test-user",
		ClusterID:   "cluster-123",
		Action:      actions.NewGetAction(),
		Target:      testTarget,
	})

	// Deliver is fire-and-forget by contract: a best-effort sink that never
	// accepts a record must not turn a completed action into a failed one.
	if result.Error != nil {
		t.Errorf("a best-effort sink failure must not fail the action: %v", result.Error)
	}
	if !result.Allowed {
		t.Error("expected Allowed=true")
	}
	if result.Output == nil {
		t.Error("expected output from a successful action")
	}

	spy := &auditSpy{auditor, sink}
	if got := len(spy.records(t)); got != 2 {
		t.Errorf("expected 2 records on the required sink, got %d", got)
	}
	// The loss is surfaced through the counter, not the caller.
	if got := auditor.Failures(); got == 0 {
		t.Error("expected the failing best-effort sink to register a permanent failure")
	}
}

func TestExecutor_Denied_EmitsOnlyActionDenied(t *testing.T) {
	bp := &fakeClientProvider{client: newFakeClient()}
	exec, auditor := newTestExecutor([]string{"openshift-logging"}, nil, bp)

	result := exec.Execute(context.Background(), Request{
		ExecutionID: "exec-denied",
		CallerID:    "test-user",
		ClusterID:   "cluster-123",
		Action:      actions.NewGetAction(),
		Target:      testTarget,
	})

	if result.Allowed {
		t.Fatal("expected the action to be denied")
	}

	records := auditor.records(t)
	// A denial never reaches WriteRequired, so there is no action.attempted —
	// an attempt record for something that was never attempted would be a lie.
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 record, got %d", len(records))
	}
	if records[0].Event != audit.EventActionDenied {
		t.Errorf("event = %q, want %q", records[0].Event, audit.EventActionDenied)
	}
	if records[0].Decision != audit.DecisionDenied {
		t.Errorf("decision = %q, want %q", records[0].Decision, audit.DecisionDenied)
	}
	if records[0].Outcome != audit.OutcomeSkipped {
		t.Errorf("outcome = %q, want %q", records[0].Outcome, audit.OutcomeSkipped)
	}
	if got := bp.Calls(); got != 0 {
		t.Errorf("backplane was called %d times on a denied action, want 0", got)
	}
}

func TestExecutor_Success_EmitsAttemptedThenCompleted(t *testing.T) {
	const execID = "exec-success"

	cm := newConfigMap("openshift-monitoring", "cluster-config")
	bp := &fakeClientProvider{client: newFakeClient(cm)}
	exec, auditor := newTestExecutor([]string{"openshift-monitoring"}, nil, bp)

	result := exec.Execute(context.Background(), Request{
		ExecutionID: execID,
		CallerID:    "test-user",
		ClusterID:   "cluster-123",
		Action:      actions.NewGetAction(),
		Target:      testTarget,
	})

	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}

	records := auditor.records(t)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	byEvent := recordsByEvent(t, records)
	attempted, ok := byEvent[audit.EventActionAttempted]
	if !ok {
		t.Fatalf("no %q record", audit.EventActionAttempted)
	}
	completed, ok := byEvent[audit.EventActionCompleted]
	if !ok {
		t.Fatalf("no %q record", audit.EventActionCompleted)
	}

	// Assert on Sequence, not slice position: WriteRequired writes inline
	// while Deliver writes from a goroutine, so arrival order is incidental.
	// Sequence is the Auditor's own counter and is what downstream orders by.
	if attempted.Sequence >= completed.Sequence {
		t.Errorf("attempted sequence %d must precede completed sequence %d",
			attempted.Sequence, completed.Sequence)
	}

	// Without a shared key the pair cannot be matched, and an attempt with no
	// completion — the only evidence an execution died mid-flight — becomes
	// undetectable.
	if attempted.ExecutionID != execID || completed.ExecutionID != execID {
		t.Errorf("execution IDs = %q / %q, want both %q",
			attempted.ExecutionID, completed.ExecutionID, execID)
	}

	// The attempt is written before anything runs, so it cannot claim an
	// outcome.
	if attempted.Outcome != "" {
		t.Errorf("attempted outcome = %q, want empty: nothing had happened yet", attempted.Outcome)
	}
	if attempted.Decision != audit.DecisionAllowed {
		t.Errorf("attempted decision = %q, want %q", attempted.Decision, audit.DecisionAllowed)
	}
	if completed.Outcome != audit.OutcomeSuccess {
		t.Errorf("completed outcome = %q, want %q", completed.Outcome, audit.OutcomeSuccess)
	}
}
