// Package governed defines the ports between governance (DOM-GOV) and the contexts that own governed
// definitions (CIC-015-001 §1), plus a generic per-schema definition store. Contexts never import each
// other; the composition root wires these ports (CIC-001-001 §3).
//
// @traces CIC-015-001 §1 §2 §6, CIC-029-001 §3, PRIN-011
package governed

import (
	"context"
	"time"
)

// Tenant identifies the tenant and acting party of an operation.
type Tenant struct {
	ID    string // uuid (RLS key)
	Slug  string
	Actor string // party URN
	Corr  string // correlation id
}

// Definition is a governed definition as stored by its owning context.
type Definition struct {
	URN          string         `json:"urn"`
	Kind         string         `json:"kind"`
	Namespace    string         `json:"namespace"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	State        string         `json:"state"`
	Body         map[string]any `json:"body"`
	Digest       string         `json:"digest"`
	ChangeSetRef string         `json:"changeSetRef,omitempty"`
	Revision     int64          `json:"revision"`
	PublishedAt  *time.Time     `json:"publishedAt,omitempty"`
}

// View resolves definitions by kind and name across all owners: published ones plus the drafts of the
// ChangeSet under validation/apply (so a pack may reference its own not-yet-published definitions).
type View interface {
	Find(kind, name string) (Definition, bool)
	All(kind string) []Definition
}

// Owner is implemented by every context that owns governed definitions.
type Owner interface {
	Kinds() []string
	// Draft stores a new draft definition and returns it (with its URN and content digest).
	Draft(ctx context.Context, t Tenant, kind string, body map[string]any, changeSetRef string) (Definition, error)
	Get(ctx context.Context, t Tenant, urn string) (Definition, error)
	List(ctx context.Context, t Tenant, states ...string) ([]Definition, error)
	// Validate checks the draft against its invariants with references resolved through v.
	Validate(ctx context.Context, t Tenant, urn string, v View) error
	// Publish moves draft → published bound to changeSetRef (after Gate approval).
	Publish(ctx context.Context, t Tenant, urn, changeSetRef string, v View) error
	// Compensate undoes Publish (saga compensation, CIC-015-001 §6).
	Compensate(ctx context.Context, t Tenant, urn string) error
	// Remove deletes a definition (uninstall, CR-029-001-03).
	Remove(ctx context.Context, t Tenant, urn string) error
	// Facts describes the definition for risk classification (layer, kernel, compatibility).
	Facts(d Definition) map[string]any
}

// Gate authorizes publication: the URN must be an item of a ChangeSet that is currently applying
// (CR-015-001-01). Implemented by governance.
type Gate interface {
	CanPublish(ctx context.Context, t Tenant, changeSetRef, urn string) error
}

// Decider is the PDP port (DOM-POL). bootstrap lists draft policies usable when no published policy of
// that name exists yet in the tenant (ADR 0005: a pack installation is governed by the governance
// policies it carries).
type Decider interface {
	Decide(ctx context.Context, t Tenant, name string, input map[string]any, bootstrap []Definition) (any, error)
	// EvalCEL evaluates a CEL expression over vars (used for risk-classification `when` rules).
	EvalCEL(expr string, vars map[string]any) (any, error)
}

// Evidence is the EVD capture port.
type Evidence interface {
	Capture(ctx context.Context, t Tenant, kind string, content map[string]any, links []Link) (string, error)
}

// Link relates evidence to a subject.
type Link struct {
	SubjectRef string `json:"subjectRef"`
	Role       string `json:"role"`
}
