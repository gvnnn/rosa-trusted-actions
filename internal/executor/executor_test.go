package executor

import (
	"context"
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

type fakeClientProvider struct {
	client dynamic.Interface
	err    error
}

func (f *fakeClientProvider) GetClient(_ context.Context, _ string, _ []backplane.RBACRule) (dynamic.Interface, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

func (f *fakeClientProvider) GetPodExecutor(_ context.Context, _ string, _ []backplane.RBACRule) (backplane.PodExecutor, error) {
	return nil, fmt.Errorf("not implemented in test fake")
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

	records := auditor.records(t)

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
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != audit.DecisionAllowed {
		t.Errorf("expected audit decision %q, got %q", audit.DecisionAllowed, records[0].Decision)
	}
	if records[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeSuccess, records[0].Outcome)
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

	records := auditor.records(t)

	if result.Allowed {
		t.Error("expected denied, got allowed")
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
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
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
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
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
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
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Outcome != audit.OutcomeFailure {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeFailure, records[0].Outcome)
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
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Outcome != audit.OutcomeFailure {
		t.Errorf("expected audit outcome %q, got %q", audit.OutcomeFailure, records[0].Outcome)
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

	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}

	rec := records[0]
	if rec.CallerID != "srep-user" {
		t.Errorf("expected caller %q, got %q", "srep-user", rec.CallerID)
	}
	if rec.ClusterID != "cluster-456" {
		t.Errorf("expected cluster %q, got %q", "cluster-456", rec.ClusterID)
	}
	if rec.Action != "get" {
		t.Errorf("expected action %q, got %q", "get", rec.Action)
	}
	if rec.Target.Resource != "configmaps" {
		t.Errorf("expected resource type %q, got %q", "configmaps", rec.Target.Resource)
	}
	if rec.Target.Namespace != "openshift-monitoring" {
		t.Errorf("expected namespace %q, got %q", "openshift-monitoring", rec.Target.Namespace)
	}
	if rec.Target.Name != "cluster-config" {
		t.Errorf("expected name %q, got %q", "cluster-config", rec.Target.Name)
	}
}
