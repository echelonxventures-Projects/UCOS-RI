// Package ctxrt is the Go implementation of ucos-context-runtime: context assembly and the context
// resolution algorithm, executable semantics per contracts/context-runtime/semantics.md.
//
// @traces CIC-011-001, DOM-CTX, CR-011-001-01..04
package ctxrt

import (
	"encoding/json"
	"sort"
)

// Dimension is a ContextDimension as seen by the runtime (semantics.md §2).
type Dimension struct {
	Code       string            `json:"code"`
	ValueType  string            `json:"valueType"`
	Weight     int64             `json:"weight"`
	Precedence int64             `json:"precedence"`
	Required   bool              `json:"required"`
	Default    any               `json:"default"`
	Normalize  string            `json:"normalize"`
	Values     []any             `json:"values"`
	Hierarchy  map[string]string `json:"hierarchy"`
	FromAsOf   bool              `json:"fromAsOf"`
}

// World is an immutable set of dimensions with precomputed lookups.
type World struct {
	ID    string
	Dims  map[string]*Dimension
	Order []string // all dimension codes by (precedence, code)
}

// NewWorld indexes dimensions.
func NewWorld(id string, dims []Dimension) *World {
	w := &World{ID: id, Dims: map[string]*Dimension{}}
	for i := range dims {
		d := dims[i]
		w.Dims[d.Code] = &d
		w.Order = append(w.Order, d.Code)
	}
	sort.Slice(w.Order, func(i, j int) bool {
		a, b := w.Dims[w.Order[i]], w.Dims[w.Order[j]]
		if a.Precedence != b.Precedence {
			return a.Precedence < b.Precedence
		}
		return a.Code < b.Code
	})
	return w
}

// Constraint is one ApplicabilityScope conjunct.
type Constraint struct {
	Dimension string `json:"dimension"`
	Op        string `json:"op"`
	Values    []any  `json:"values"`
}

// Candidate is a scoped contextual fact.
type Candidate struct {
	ID        string          `json:"id"`
	Scope     []Constraint    `json:"scope"`
	ValidFrom string          `json:"validFrom"`
	ValidTo   *string         `json:"validTo"`
	Priority  int64           `json:"priority"`
	Value     json.RawMessage `json:"value"`
}

// Context is an assembled ContextVector.
type Context struct {
	Values                  map[string]any `json:"values"`
	AsOf                    string         `json:"asOf"`
	CacheGranularitySeconds int64          `json:"cacheGranularitySeconds"`
}

// Config is a ResolutionConfig.
type Config struct {
	DimensionPrecedence []string `json:"dimensionPrecedence"`
	ConflictStrategy    string   `json:"conflictStrategy"`
	Cardinality         string   `json:"cardinality"`
	RelaxationAllowed   bool     `json:"relaxationAllowed"`
	FallbackChains      []string `json:"fallbackChains"`
	MaxFallbackSteps    *int64   `json:"maxFallbackSteps"`
	ConfigRef           *string  `json:"configRef"`
}

// RankEntry is one trace.ranking element.
type RankEntry struct {
	ID          string
	Specificity int64
	Priority    int64
}

// Conflict is trace.conflict.
type Conflict struct {
	Strategy string
	Tied     []string
}

// Trace is the resolution trace (CIC-011-001 §4).
type Trace struct {
	FactKind      string
	ContextDigest string
	Candidates    int
	AfterTemporal int
	Matched       int
	FallbackPath  []string
	Ranking       []RankEntry
	Conflict      *Conflict
	Selected      *string
	ConfigRef     *string
}

// Resolution is the result of Resolve.
type Resolution struct {
	Status   string
	Selected []string
	Value    any
	Code     *string
	Trace    Trace
}

// Canonical renders the resolution in the protocol shape.
func (r Resolution) Canonical() any {
	ranking := make([]any, 0, len(r.Trace.Ranking))
	for _, e := range r.Trace.Ranking {
		ranking = append(ranking, map[string]any{"id": e.ID, "specificity": e.Specificity, "priority": e.Priority})
	}
	var conflict any
	if r.Trace.Conflict != nil {
		conflict = map[string]any{"strategy": r.Trace.Conflict.Strategy, "tied": r.Trace.Conflict.Tied}
	}
	return map[string]any{
		"status": r.Status, "selected": nonNil(r.Selected), "value": r.Value, "code": strOrNil(r.Code),
		"trace": map[string]any{
			"factKind": r.Trace.FactKind, "contextDigest": r.Trace.ContextDigest,
			"candidates": r.Trace.Candidates, "afterTemporal": r.Trace.AfterTemporal, "matched": r.Trace.Matched,
			"fallbackPath": nonNil(r.Trace.FallbackPath), "ranking": ranking, "conflict": conflict,
			"selected": strOrNil(r.Trace.Selected), "configRef": strOrNil(r.Trace.ConfigRef),
		},
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func strOrNil(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func ptr(s string) *string { return &s }
