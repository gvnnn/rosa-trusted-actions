package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
	"github.com/openshift-online/rosa-trusted-actions/internal/audit"
	"github.com/openshift-online/rosa-trusted-actions/internal/authorization"
	"github.com/openshift-online/rosa-trusted-actions/internal/backplane"
)

// ErrAuditUnavailable means no privileged side effect was attempted: the
// required audit sinks would not accept the pre-execution record, so the
// action was refused rather than run unrecorded.
var ErrAuditUnavailable = errors.New("audit trail unavailable; action not executed")

type Request struct {
	// ExecutionID ties the action.attempted and action.completed records
	ExecutionID    string
	CallerID       string
	ClusterID      string
	ClusterVersion string
	Action         actions.Action
	Target         actions.ResourceTarget
	Params         map[string]string
}

type Result struct {
	Allowed bool
	Reason  string
	Output  *actions.ActionResult
	Error   error
}

type Executor struct {
	logger     *logrus.Logger
	authorizer authorization.Authorizer
	auditor    *audit.Auditor
	backplane  backplane.ClientProvider
}

func New(
	logger *logrus.Logger,
	authorizer authorization.Authorizer,
	auditor *audit.Auditor,
	bp backplane.ClientProvider,
) *Executor {
	return &Executor{
		logger:     logger,
		authorizer: authorizer,
		auditor:    auditor,
		backplane:  bp,
	}
}

func (e *Executor) Execute(ctx context.Context, req Request) (result *Result) {
	// Timestamp is deliberately left zero: Auditor.stamp fills it at emit
	// time, so each record carries when *it* happened rather than when
	// Execute started
	base := audit.Record{
		ExecutionID: req.ExecutionID,
		CallerID:    req.CallerID,
		Action:      req.Action.Name(),
		Target:      req.Target,
		ClusterID:   req.ClusterID,
	}

	authResult := e.authorizer.Authorize(authorization.Request{
		Namespace:     req.Target.Namespace,
		ResourceType:  req.Target.Resource,
		ResourceName:  req.Target.Name,
		ClusterScoped: req.Target.ClusterScoped,
	})

	if !authResult.Allowed {
		denied := base
		denied.Event = audit.EventActionDenied
		denied.Decision = audit.DecisionDenied
		denied.DenyReason = authResult.Reason
		denied.Outcome = audit.OutcomeSkipped
		// Deliberately not fail-closed: a denial has no side effect to
		// prevent, losing one is an audit gap rather than a safety breach,
		// and there is no coherent way to refuse to deny.
		e.auditor.Deliver(ctx, denied)

		return &Result{Allowed: false, Reason: authResult.Reason}
	}

	base.Decision = audit.DecisionAllowed

	// The invariant: this record must be durable before anything privileged
	// happens. Nothing below this line runs if it is not.
	attempted := base
	attempted.Event = audit.EventActionAttempted
	if err := e.auditor.WriteRequired(ctx, attempted); err != nil {
		e.logger.WithFields(logrus.Fields{
			"caller":       req.CallerID,
			"action":       req.Action.Name(),
			"cluster_id":   req.ClusterID,
			"execution_id": req.ExecutionID,
		}).WithError(err).Error("Audit trail unavailable; refusing to execute")

		// Allowed stays true: authorization permitted this. Reporting it as
		// denied would misattribute an infrastructure failure to the caller's
		// permissions and corrupt denial metrics.
		return &Result{
			Allowed: true,
			Reason:  authResult.Reason,
			Error:   ErrAuditUnavailable,
		}
	}

	// Past this point a side effect may occur, so a completion record is owed
	// however the action exits. The closure captures the variable, so the
	// mutations below are visible when it runs.
	//
	// Do not move this defer before the WriteRequired call above, least
	// audit sink failures might still emit an action.completed event.
	completed := base
	completed.Event = audit.EventActionCompleted
	defer func() { e.auditor.Deliver(ctx, completed) }()

	// Each primitive action gets its own backplane session scoped to exactly the
	// RBAC it needs (least-privilege). Composite actions could merge RBAC rules
	// from all sub-actions and call GetClient once to reuse a single session.
	// (possible design decision for later)
	rbacRules := req.Action.RequiredRBAC(req.Target)
	client, err := e.backplane.GetClient(ctx, req.ClusterID, rbacRules)
	if err != nil {
		completed.Outcome = audit.OutcomeFailure
		completed.Error = err.Error()
		return &Result{
			Allowed: true,
			Reason:  authResult.Reason,
			Error:   fmt.Errorf("failed to get cluster client: %w", err),
		}
	}

	clients := actions.Clients{Dynamic: client}

	if req.Action.UsesPodExec() {
		podExec, podErr := e.backplane.GetPodExecutor(ctx, req.ClusterID, rbacRules)
		if podErr != nil {
			completed.Outcome = audit.OutcomeFailure
			completed.Error = podErr.Error()
			return &Result{
				Allowed: true,
				Reason:  authResult.Reason,
				Error:   fmt.Errorf("failed to get pod executor: %w", podErr),
			}
		}
		clients.PodExecutor = podExec
	}

	actionReq := actions.ActionRequest{
		Target:         req.Target,
		ClusterVersion: req.ClusterVersion,
		Params:         req.Params,
	}
	output, err := req.Action.Execute(ctx, clients, actionReq)
	if err != nil {
		completed.Outcome = audit.OutcomeFailure
		completed.Error = err.Error()
		return &Result{
			Allowed: true,
			Reason:  authResult.Reason,
			Error:   fmt.Errorf("action execution failed: %w", err),
		}
	}

	completed.Outcome = audit.OutcomeSuccess
	return &Result{
		Allowed: true,
		Reason:  authResult.Reason,
		Output:  output,
	}
}
