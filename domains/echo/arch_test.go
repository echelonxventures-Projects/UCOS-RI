// Architecture test (CR-001-001-01): the §3 dependency rule api ← domain ← application ← infrastructure ← service,
// and a pure domain (no I/O imports).
package echo_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const mod = "ucos.dev/ri/echo/"

// allowed lists, per layer, the module layers it may import.
var allowed = map[string][]string{
	"api":            {},
	"domain":         {},
	"application":    {"api", "domain"},
	"infrastructure": {"application", "domain"},
	"service":        {"api", "application", "domain"},
	"cmd":            {"application", "infrastructure", "service"},
}

// domainStdlib is the allow-list of standard packages for the pure domain layer.
var domainStdlib = map[string]bool{"errors": true, "fmt": true, "strings": true, "time": true, "unicode/utf8": true,
	"testing": true}

func TestDependencyRule(t *testing.T) {
	for layer, ok := range allowed {
		err := filepath.WalkDir(layer, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, mod) {
					target := strings.SplitN(strings.TrimPrefix(p, mod), "/", 2)[0]
					if target != layer && !contains(ok, target) {
						t.Errorf("%s: layer %s must not import %s", path, layer, target)
					}
				} else if layer == "domain" && !domainStdlib[p] {
					t.Errorf("%s: domain must stay pure, imports %s", path, p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
