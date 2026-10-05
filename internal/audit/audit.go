package audit

import (
	"context"
	"time"

	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
)

type Event string

const (
	EventActionDenied    Event = "action.denied"
	EventActionAttempted Event = "action.attempted"
	EventActionCompleted Event = "action.completed"
)

type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeSkipped Outcome = "skipped"
)

type Record struct {
	ID        string    `json:"id"`
	Sequence  uint64    `json:"sequence"`
	Timestamp time.Time `json:"timestamp"`
	Event     Event     `json:"event"`

	CallerID   string                 `json:"caller_id"`
	Action     string                 `json:"action"`
	Target     actions.ResourceTarget `json:"target"`
	ClusterID  string                 `json:"cluster_id"`
	Decision   Decision               `json:"decision,omitempty"`
	DenyReason string                 `json:"deny_reason,omitempty"`
	Outcome    Outcome                `json:"outcome,omitempty"`
	Error      string                 `json:"error,omitempty"`

	ExecutionID string `json:"execution_id,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

// Sink is a destination for audit records. Implementations must be safe for
// concurrent use and must not retry internally: retry policy belongs to the
// Auditor so it applies uniformly across sinks.
type Sink interface {
	// Name identifies the sink in logs, health output, and config errors.
	Name() string
	// Write delivers a single record. Return nil only once the sink's backend
	// has confirmed the record as far as the backend allows (e.g. file-based sink's
	// sync() has returned, CloudWatch returns 200 OK, network sink ACKs, etc.)
	// Never return nil merely because the bytes were handed to a buffer: a required sink's
	// nil is what permits a privileged action to proceed, i.e. an audit record has been safely
	// stored.
	Write(ctx context.Context, rec Record) error
}
