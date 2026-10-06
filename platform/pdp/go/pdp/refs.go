package pdp

import (
	"fmt"
	"sort"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
)

// References compiles expr over the variables roots and returns the maximal field paths it reads from them, as
// dotted strings (`object.values.brand`; constant-string indexes `relations['X']` count as fields). A path that
// stops at a map (`object.values`) means the expression reads the whole map. This is the dependency set of a
// compiled selector (DOM-CAT SelectorCompiler).
func (e *Engine) References(expr string, roots []string) ([]string, error) {
	var opts []cel.EnvOption
	for _, r := range roots {
		opts = append(opts, cel.Variable(r, cel.DynType))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, err
	}
	a, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("CEL does not compile: %v", iss.Err())
	}
	isRoot := map[string]bool{}
	for _, r := range roots {
		isRoot[r] = true
	}
	found := map[string]bool{}
	var walk func(x ast.Expr)
	walk = func(x ast.Expr) {
		if p, root, ok := path(x); ok {
			if isRoot[root] {
				found[p] = true
			}
			return
		}
		switch x.Kind() {
		case ast.CallKind:
			c := x.AsCall()
			if c.IsMemberFunction() {
				walk(c.Target())
			}
			for _, arg := range c.Args() {
				walk(arg)
			}
		case ast.SelectKind:
			walk(x.AsSelect().Operand())
		case ast.ListKind:
			for _, el := range x.AsList().Elements() {
				walk(el)
			}
		case ast.MapKind:
			for _, en := range x.AsMap().Entries() {
				walk(en.AsMapEntry().Key())
				walk(en.AsMapEntry().Value())
			}
		case ast.StructKind:
			for _, f := range x.AsStruct().Fields() {
				walk(f.AsStructField().Value())
			}
		case ast.ComprehensionKind:
			c := x.AsComprehension()
			walk(c.IterRange())
			walk(c.AccuInit())
			walk(c.LoopCondition())
			walk(c.LoopStep())
			walk(c.Result())
		}
	}
	walk(a.NativeRep().Expr())
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// path renders an identifier followed by field selections and constant-string indexes.
func path(x ast.Expr) (string, string, bool) {
	switch x.Kind() {
	case ast.IdentKind:
		return x.AsIdent(), x.AsIdent(), true
	case ast.SelectKind:
		s := x.AsSelect()
		if p, root, ok := path(s.Operand()); ok {
			return p + "." + s.FieldName(), root, true
		}
	case ast.CallKind:
		c := x.AsCall()
		if c.FunctionName() == "_[_]" && len(c.Args()) == 2 && c.Args()[1].Kind() == ast.LiteralKind {
			if lit, ok := c.Args()[1].AsLiteral().(types.String); ok {
				if p, root, ok := path(c.Args()[0]); ok {
					return p + "." + string(lit), root, true
				}
			}
		}
	}
	return "", "", false
}
