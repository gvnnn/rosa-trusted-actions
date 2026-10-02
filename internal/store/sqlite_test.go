package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/openshift-online/rosa-trusted-actions/internal/models"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(context.Background(), ":memory:", logrus.New())
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close test store: %v", err)
		}
	})
	return s
}

func testExecution(action, target string) *models.Execution {
	now := time.Now().UTC().Truncate(time.Microsecond)
	approvalState := "not_required"
	username := "test-user"
	jira := "ROSAENG-1234"
	return &models.Execution{
		ID:            uuid.New(),
		Action:        action,
		Status:        "pending",
		ApprovalState: &approvalState,
		Username:      &username,
		TargetCluster: target,
		Jira:          &jira,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestSQLiteStore_CreateExecution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	exec := testExecution("cluster-info", "test-cluster")
	params := json.RawMessage(`{"namespace":"default"}`)
	exec.Params = &params
	dryRun := true
	exec.DryRun = &dryRun

	if err := s.CreateExecution(ctx, exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	{
		got, err := s.GetExecution(ctx, exec.ID)
		if err != nil {
			t.Fatalf("GetExecution failed: %v", err)
		}

		if got.ID != exec.ID {
			t.Errorf("ID: got %v, want %v", got.ID, exec.ID)
		}
		if got.Action != exec.Action {
			t.Errorf("Action: got %v, want %v", got.Action, exec.Action)
		}
		if got.Status != exec.Status {
			t.Errorf("Status: got %v, want %v", got.Status, exec.Status)
		}
		if got.TargetCluster != exec.TargetCluster {
			t.Errorf("TargetCluster: got %v, want %v", got.TargetCluster, exec.TargetCluster)
		}
		if got.DryRun == nil || *got.DryRun != true {
			t.Errorf("DryRun: got %v, want true", got.DryRun)
		}
		if got.Params == nil {
			t.Fatal("Params: got nil, want non-nil")
		}
		if string(*got.Params) != `{"namespace":"default"}` {
			t.Errorf("Params: got %s, want %s", string(*got.Params), `{"namespace":"default"}`)
		}
	}

	{
		got, err := s.GetExecutionOutput(ctx, exec.ID)
		if err == nil {
			t.Errorf("GetExecutionOutput succeeded")
		}
		if got != nil {
			t.Errorf("ExecutionOutput: got %v, want nothing", got)
		}
	}
}

func TestSQLiteStore_GetExecution_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetExecution(ctx, uuid.New())
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_GetExecutionOuput_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetExecutionOutput(ctx, uuid.New())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_ListExecutions_NoFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	exec1 := testExecution("cluster-info", "cluster-1")
	exec2 := testExecution("pod-restart", "cluster-2")
	exec2.CreatedAt = exec2.CreatedAt.Add(time.Second)
	exec2.UpdatedAt = exec2.UpdatedAt.Add(time.Second)

	if err := s.CreateExecution(ctx, exec1); err != nil {
		t.Fatalf("CreateExecution exec1 failed: %v", err)
	}
	if err := s.CreateExecution(ctx, exec2); err != nil {
		t.Fatalf("CreateExecution exec2 failed: %v", err)
	}

	result, err := s.ListExecutions(ctx, ExecutionFilter{})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}

	if result.Total != 2 {
		t.Errorf("Total: got %d, want 2", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("Items: got %d, want 2", len(result.Items))
	}
	if result.Items[0].Action != "pod-restart" {
		t.Errorf("first item should be pod-restart (newest), got %s", result.Items[0].Action)
	}
}

func TestSQLiteStore_ListExecutions_FilterByStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	exec1 := testExecution("cluster-info", "cluster-1")
	exec2 := testExecution("pod-restart", "cluster-2")
	exec2.Status = "running"

	if err := s.CreateExecution(ctx, exec1); err != nil {
		t.Fatalf("CreateExecution exec1 failed: %v", err)
	}
	if err := s.CreateExecution(ctx, exec2); err != nil {
		t.Fatalf("CreateExecution exec2 failed: %v", err)
	}

	status := "running"
	result, err := s.ListExecutions(ctx, ExecutionFilter{Status: &status})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total: got %d, want 1", result.Total)
	}
	if result.Items[0].Action != "pod-restart" {
		t.Errorf("Action: got %s, want pod-restart", result.Items[0].Action)
	}
}

func TestSQLiteStore_ListExecutions_FilterByAction(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateExecution(ctx, testExecution("cluster-info", "cluster-1")); err != nil {
		t.Fatalf("CreateExecution cluster-info failed: %v", err)
	}
	if err := s.CreateExecution(ctx, testExecution("pod-restart", "cluster-2")); err != nil {
		t.Fatalf("CreateExecution pod-restart failed: %v", err)
	}

	action := "cluster-info"
	result, err := s.ListExecutions(ctx, ExecutionFilter{Action: &action})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total: got %d, want 1", result.Total)
	}
}

func TestSQLiteStore_ListExecutions_Limit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		exec := testExecution("cluster-info", "cluster-1")
		exec.CreatedAt = exec.CreatedAt.Add(time.Duration(i) * time.Second)
		exec.UpdatedAt = exec.UpdatedAt.Add(time.Duration(i) * time.Second)
		if err := s.CreateExecution(ctx, exec); err != nil {
			t.Fatalf("CreateExecution[%d] failed: %v", i, err)
		}
	}

	result, err := s.ListExecutions(ctx, ExecutionFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListExecutions failed: %v", err)
	}

	if result.Total != 5 {
		t.Errorf("Total: got %d, want 5", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("Items: got %d, want 2", len(result.Items))
	}
}

func TestSQLiteStore_UpdateExecutionStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	exec := testExecution("cluster-info", "cluster-1")
	if err := s.CreateExecution(ctx, exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	err := s.UpdateExecutionWithResult(ctx, exec.ID, "succeeded", &completedAt, nil)
	if err != nil {
		t.Fatalf("UpdateExecutionStatus failed: %v", err)
	}

	{
		got, err := s.GetExecution(ctx, exec.ID)
		if err != nil {
			t.Fatalf("GetExecution failed: %v", err)
		}
		if got.Status != "succeeded" {
			t.Errorf("Status: got %s, want succeeded", got.Status)
		}
		if got.CompletedAt == nil {
			t.Fatal("CompletedAt: got nil, want non-nil")
		}
	}
	{
		got, err := s.GetExecutionOutput(ctx, exec.ID)
		if err == nil {
			t.Errorf("GetExecutionOutput succeeded")
		}
		if got != nil {
			t.Errorf("ExecutionOutput: got %v, want nothing", got)
		}
	}
}

func TestSQLiteStore_UpdateExecutionStatusAndOutput(t *testing.T) {
	g := NewWithT(t)
	s := newTestStore(t)
	ctx := context.Background()

	exec := testExecution("cluster-info", "cluster-1")
	err := s.CreateExecution(ctx, exec)
	g.Expect(err).ToNot(HaveOccurred())

	completedAt := time.Now().UTC().Truncate(time.Microsecond)
	message := "execution logs"
	resources := []map[string]interface{}{
		{
			"name":     "object1",
			"data":     "some data",
			"some-key": "some value",
		},
		{
			"name":   "object2",
			"data":   "some other data",
			"secret": "can't say",
		},
	}

	err = s.UpdateExecutionWithResult(ctx, exec.ID, "succeeded", &completedAt, &models.ExecutionOutput{
		Message:   message,
		Resources: resources,
	})
	g.Expect(err).ToNot(HaveOccurred())

	{
		got, err := s.GetExecution(ctx, exec.ID)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).ToNot(BeNil())
		g.Expect(got.Status).To(Equal("succeeded"))
		g.Expect(got.CompletedAt).ToNot(BeNil())
	}
	{
		got, err := s.GetExecutionOutput(ctx, exec.ID)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).ToNot(BeNil())
		g.Expect(got.Message).To(Equal(message))
		g.Expect(got.Resources).To(Equal(resources))
	}
}

func TestSQLiteStore_UpdateExecutionStatus_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.UpdateExecutionWithResult(ctx, uuid.New(), "succeeded", nil, nil)
	if !strings.Contains(err.Error(), ErrNotFound.Error()) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_ClaimNextExecution(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	older := testExecution("cluster-info", "cluster-1")
	newer := testExecution("pod-restart", "cluster-2")
	newer.CreatedAt = newer.CreatedAt.Add(time.Second)
	newer.UpdatedAt = newer.UpdatedAt.Add(time.Second)

	if err := s.CreateExecution(ctx, newer); err != nil {
		t.Fatalf("CreateExecution newer failed: %v", err)
	}
	if err := s.CreateExecution(ctx, older); err != nil {
		t.Fatalf("CreateExecution older failed: %v", err)
	}

	claimed, err := s.ClaimNextExecution(ctx)
	if err != nil {
		t.Fatalf("ClaimNextExecution failed: %v", err)
	}
	if claimed.ID != older.ID {
		t.Errorf("expected to claim the oldest pending execution (%s), got %s", older.ID, claimed.ID)
	}
	if claimed.Status != "running" {
		t.Errorf("Status: got %s, want running", claimed.Status)
	}

	got, err := s.GetExecution(ctx, older.ID)
	if err != nil {
		t.Fatalf("GetExecution failed: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("persisted status: got %s, want running", got.Status)
	}

	claimed2, err := s.ClaimNextExecution(ctx)
	if err != nil {
		t.Fatalf("second ClaimNextExecution failed: %v", err)
	}
	if claimed2.ID != newer.ID {
		t.Errorf("expected to claim the remaining pending execution (%s), got %s", newer.ID, claimed2.ID)
	}
}

func TestSQLiteStore_ClaimNextExecution_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.ClaimNextExecution(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	exec := testExecution("cluster-info", "cluster-1")
	exec.Status = "running"
	if err := s.CreateExecution(ctx, exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	if _, err := s.ClaimNextExecution(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound (only a running execution exists), got %v", err)
	}
}

func TestSQLiteStore_MigrationsIdempotent(t *testing.T) {
	s := newTestStore(t)

	if err := runMigrations(context.Background(), s.db); err != nil {
		t.Fatalf("running migrations a second time should not error: %v", err)
	}
}

func TestSQLiteStore_RollbackLastMigration(t *testing.T) {
	s := newTestStore(t)

	if err := RollbackLastMigration(context.Background(), s.db); err != nil {
		t.Fatalf("RollbackLastMigration failed: %v", err)
	}

	// Rolling back 005 drops the executions_output table and its index, and
	// restores the output_path/output_status columns on executions.
	var version string
	if err := s.db.Get(&version, "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1"); err != nil {
		t.Fatalf("querying schema_migrations: %v", err)
	}
	if version == "005_create_executions_output" {
		t.Error("expected migration 005 to be removed from schema_migrations after rollback")
	}

	var indexCount int
	if err := s.db.Get(&indexCount, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_executions_output_exec_id'"); err != nil {
		t.Fatalf("querying sqlite_master: %v", err)
	}
	if indexCount != 0 {
		t.Error("expected idx_executions_output_exec_id to be dropped after rolling back the last migration")
	}
}

func TestSQLiteStore_RollbackAndReapply(t *testing.T) {
	s := newTestStore(t)

	var before int
	if err := s.db.Get(&before, "SELECT COUNT(*) FROM schema_migrations"); err != nil {
		t.Fatalf("querying migration count: %v", err)
	}

	if err := RollbackLastMigration(context.Background(), s.db); err != nil {
		t.Fatalf("RollbackLastMigration failed: %v", err)
	}

	var during int
	if err := s.db.Get(&during, "SELECT COUNT(*) FROM schema_migrations"); err != nil {
		t.Fatalf("querying migration count after rollback: %v", err)
	}
	if during != before-1 {
		t.Errorf("expected %d migrations after rollback, got %d", before-1, during)
	}

	if err := runMigrations(context.Background(), s.db); err != nil {
		t.Fatalf("re-running migrations after rollback failed: %v", err)
	}

	var after int
	if err := s.db.Get(&after, "SELECT COUNT(*) FROM schema_migrations"); err != nil {
		t.Fatalf("querying migration count after reapply: %v", err)
	}
	if after != before {
		t.Errorf("expected %d migrations after reapply, got %d", before, after)
	}
}
