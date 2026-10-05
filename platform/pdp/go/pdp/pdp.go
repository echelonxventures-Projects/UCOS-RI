// Package pdp is the embeddable policy decision point (CIC-009-001 §5: "PDP is embedded (library, bundle sync)
// in every service"). It evaluates policy bodies — `static` configuration or `cel` expressions — over an input
// and context, and compares outputs numerically as the corpus validator does.
//
// @traces CIC-009-001, DOM-POL, INV-POL-1, PRIN-005
package pdp

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// Engine caches compiled CEL programs per (expression, variable set).
type Engine struct {
	mu    sync.Mutex
	progs map[string]cel.Program
}

// Evaluate runs a policy body {language, source} for input (top-level variables) and ctx (variable `ctx`).
func (e *Engine) Evaluate(body map[string]any, input, ctx map[string]any) (any, error) {
	lang, _ := body["language"].(string)
	switch lang {
	case "static":
		return body["source"], nil
	case "cel":
		vars := map[string]any{}
		for k, v := range input {
			vars[k] = v
		}
		if ctx == nil {
			ctx = map[string]any{}
		}
		vars["ctx"] = ctx
		src, _ := body["source"].(string)
		return e.EvalCEL(src, vars)
	}
	return nil, fmt.Errorf("unsupported body language %q", lang)
}

// EvalCEL compiles (cached) and evaluates expr over vars (cost-limited, no I/O functions).
func (e *Engine) EvalCEL(expr string, vars map[string]any) (any, error) {
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	key := strings.Join(names, ",") + "\x00" + expr
	e.mu.Lock()
	if e.progs == nil {
		e.progs = map[string]cel.Program{}
	}
	prg, ok := e.progs[key]
	e.mu.Unlock()
	if !ok {
		var opts []cel.EnvOption
		for _, n := range names {
			opts = append(opts, cel.Variable(n, cel.DynType))
		}
		env, err := cel.NewEnv(opts...)
		if err != nil {
			return nil, err
		}
		ast, iss := env.Compile(expr)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("CEL does not compile: %v", iss.Err())
		}
		prg, err = env.Program(ast, cel.CostLimit(100000))
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.progs[key] = prg
		e.mu.Unlock()
	}
	act := map[string]any{}
	for k, v := range vars {
		act[k] = ToNative(v)
	}
	out, _, err := prg.Eval(act)
	if err != nil {
		return nil, err
	}
	return fromCEL(out), nil
}

// ToNative converts json.Number trees to int64/float64.
func ToNative(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case int:
		return int64(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = ToNative(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = ToNative(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	}
	return v
}

func fromCEL(v ref.Val) any {
	switch x := v.(type) {
	case types.Bool:
		return bool(x)
	case types.Int:
		return int64(x)
	case types.Uint:
		return int64(x)
	case types.Double:
		return float64(x)
	case types.String:
		return string(x)
	case types.Null:
		return nil
	}
	if l, ok := v.(traits.Lister); ok {
		out := []any{}
		it := l.Iterator()
		for it.HasNext() == types.True {
			out = append(out, fromCEL(it.Next()))
		}
		return out
	}
	if m, ok := v.(traits.Mapper); ok {
		out := map[string]any{}
		it := m.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			out[fmt.Sprint(fromCEL(k))] = fromCEL(m.Get(k))
		}
		return out
	}
	nv, err := v.ConvertToNative(reflect.TypeOf((*any)(nil)).Elem())
	if err != nil {
		return v.Value()
	}
	return nv
}

// Equal compares JSON-like values numerically (1 == 1.0).
func Equal(a, b any) bool {
	a, b = ToNative(a), ToNative(b)
	switch x := a.(type) {
	case int64, float64:
		fa, ok1 := num(x)
		fb, ok2 := num(b)
		return ok1 && ok2 && fa == fb
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if w, ok := y[k]; !ok || !Equal(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int64:
		return float64(x), true
	case float64:
		return x, !math.IsNaN(x)
	}
	return 0, false
}

// Decision is an authorization outcome with obligations (CIC-009-001).
type Decision struct {
	Effect      string           `json:"effect"`
	Obligations []map[string]any `json:"obligations,omitempty"`
	Reason      string           `json:"reason,omitempty"`
}

// AsDecision reads an authorization policy output.
func AsDecision(out any) Decision {
	m, _ := out.(map[string]any)
	d := Decision{Effect: "deny"}
	if e, ok := m["effect"].(string); ok {
		d.Effect = e
	}
	if l, ok := m["obligations"].([]any); ok {
		for _, x := range l {
			if o, ok := x.(map[string]any); ok {
				d.Obligations = append(d.Obligations, o)
			}
		}
	}
	if r, ok := m["reason"].(string); ok {
		d.Reason = r
	}
	return d
}
