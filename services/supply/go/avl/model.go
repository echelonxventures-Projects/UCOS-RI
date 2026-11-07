package avl

import (
	"time"
)

// DOM-AVL value objects and read models (CIC-011-006 §1 for AvailabilityResult).

// Rule is a sellability rule (fact kind sellability-rule, owning context supply, regulated).
// Conflict 'all' with deny-overrides; every deny carries a reason code (RUL-AVL-1).
type Rule struct {
	ID         string             `json:"id"`
	Code       string             `json:"code"`
	ObjectRef  string             `json:"objectRef,omitempty"`
	TypeRef    string             `json:"typeRef,omitempty"`
	Effect     string             `json:"effect"` // allow | deny
	ReasonCode string             `json:"reasonCode,omitempty"`
	Scope      []map[string]any   `json:"scope"`      // context constraints (jurisdiction, market, channel)
	Condition  string             `json:"condition"`  // optional CEL over object values + context
	Regulated  bool               `json:"regulated"`
	ValidFrom  time.Time          `json:"validFrom"`
	ValidTo    *time.Time         `json:"validTo,omitempty"`
	Revision   int64              `json:"revision"`
}

// SourcingPolicy is a SourcingPolicy aggregate (INV-AVL-1: nodes exist and are active).
type SourcingPolicy struct {
	ID            string           `json:"id"`
	Scope         []map[string]any `json:"scope"`
	CandidateNodes []CandidateNode  `json:"candidateNodes"`
	SplitPolicy   string           `json:"splitPolicy"` // allow | deny | allow-with-penalty
	Weights       ObjectiveWeights `json:"weights"`
	ValidFrom     time.Time        `json:"validFrom"`
	ValidTo       *time.Time       `json:"validTo,omitempty"`
	Revision      int64            `json:"revision"`
}

// CandidateNode is one node of a sourcing policy.
type CandidateNode struct {
	NodeRef       string   `json:"nodeRef"`
	Priority      int64    `json:"priority"`
	Cost          string   `json:"cost"`          // relative shipping cost weight
	MaxDistanceKm *int64   `json:"maxDistanceKm,omitempty"`
	AllowedFacets []string `json:"allowedFacets,omitempty"`
}

// ObjectiveWeights are the sourcing objective weights (policy availability.sourcing-objective).
type ObjectiveWeights struct {
	Cost   int64 `json:"cost"`
	Time   int64 `json:"time"`
	Splits int64 `json:"splits"`
}

// NodeCalendar is a NodeCalendar aggregate (RUL-AVL-3).
type NodeCalendar struct {
	ID        string           `json:"id"`
	NodeRef   string           `json:"nodeRef"`
	Timezone  string           `json:"timezone"`
	WorkingHours []map[string]any `json:"workingHours"`
	Holidays  []string         `json:"holidays"`
	CutOffs   []CutOff         `json:"cutOffs"`
	Revision  int64            `json:"revision"`
}

// CutOff is a service-level cut-off time in the node's timezone.
type CutOff struct {
	ServiceLevel string `json:"serviceLevel"`
	Time         string `json:"time"` // "HH:MM"
}

// LeadTime is a LeadTime aggregate.
type LeadTime struct {
	ID                string           `json:"id"`
	Scope             []map[string]any `json:"scope"`
	ProcessingDuration string          `json:"processingDuration"`
	TransitDuration    string          `json:"transitDuration"`
	Revision          int64            `json:"revision"`
}

// AvailabilityResult is CIC-011-006 §1.
type AvailabilityResult struct {
	ObjectRef   string         `json:"objectRef"`
	Status      string         `json:"status"`
	ATP         string         `json:"atp,omitempty"`
	PromiseDate string         `json:"promiseDate,omitempty"`
	Nodes       []NodeATP      `json:"nodes,omitempty"`
	Reasons     []string       `json:"reasons,omitempty"`
	ValidUntil  time.Time      `json:"validUntil"`
	Explain     *Explanation   `json:"explanation,omitempty"`
}

// NodeATP is one node's contribution to ATP.
type NodeATP struct {
	NodeRef   string `json:"nodeRef"`
	ATP       string `json:"atp"`
	LeadTime  string `json:"leadTime,omitempty"`
	PromiseDate string `json:"promiseDate,omitempty"`
}

// Explanation is the ExplainAvailability output (DEC-AVL-1 trace).
type Explanation struct {
	Sellability []RuleHit   `json:"sellability"`
	ATP         []ATPComponent `json:"atp"`
	Trace       []string    `json:"trace"`
}

// RuleHit is one matched sellability rule.
type RuleHit struct {
	Code       string `json:"code"`
	Effect     string `json:"effect"`
	ReasonCode string `json:"reasonCode,omitempty"`
}

// ATPComponent is one term of the ATP formula (CIC-011-006 §2).
type ATPComponent struct {
	NodeRef    string `json:"nodeRef"`
	OnHand     string `json:"onHand"`
	Reserved   string `json:"reserved"`
	SafetyStock string `json:"safetyStock"`
	Inbound    string `json:"inbound"`
	ATP        string `json:"atp"`
}

// SourcingPlan is the DecideSourcing output: per-line node assignment with promise dates and totals.
type SourcingPlan struct {
	Lines  []SourcedLine  `json:"lines"`
	Totals PlanTotals     `json:"totals"`
	Exact  bool           `json:"exact"`
}

// SourcedLine is one line of a sourcing plan.
type SourcedLine struct {
	LineID      string `json:"lineId"`
	ObjectRef   string `json:"objectRef"`
	NodeRef     string `json:"nodeRef"`
	Quantity    string `json:"quantity"`
	PromiseDate string `json:"promiseDate,omitempty"`
	Cost        string `json:"cost,omitempty"`
}

// PlanTotals are the plan's weighted objective totals.
type PlanTotals struct {
	Cost    string `json:"cost"`
	Time    string `json:"time"`
	Splits  int    `json:"splits"`
	Score   string `json:"score"`
}

// PromiseWindow is the ComputePromise output (AVL-C3).
type PromiseWindow struct {
	LineID       string    `json:"lineId"`
	Earliest     time.Time `json:"earliest"`
	Latest       time.Time `json:"latest,omitempty"`
	ServiceLevel string    `json:"serviceLevel,omitempty"`
	Confidence   string    `json:"confidence,omitempty"`
	LocalDate    string    `json:"localDate,omitempty"` // destination-local date (RUL-AVL-3)
}

// Position is one row of the ATP projection (DOM-INV view).
type Position struct {
	ObjectRef   string     `json:"objectRef"`
	NodeRef     string     `json:"nodeRef"`
	OnHand      string     `json:"onHand"`
	Reserved    string     `json:"reserved"`
	SafetyStock string     `json:"safetyStock"`
	Inbound     string     `json:"inbound"`
	InboundAt   *time.Time `json:"inboundAt,omitempty"`
	Version     int64      `json:"version"`
}

// Objects resolves commercial objects for sellability evaluation (DOM-COB through commerce-service).
type Objects interface {
	// View returns the object's resolved values and its type ref; found=false when the object is unreadable.
	View(tenant, ref string) (values map[string]any, typeRef string, found bool)
}

// Status classification (AvailabilityStatus machine, DOM-AVL).
const (
	StatusAvailable   = "available"
	StatusLimited     = "limited"
	StatusBackorder   = "backorder"
	StatusPreorder    = "preorder"
	StatusUnavailable = "unavailable"
	StatusNotSellable = "not-sellable"
)
