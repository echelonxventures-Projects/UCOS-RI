// Architecture test (CR-001-001-01): kernel contexts never import each other; they share only the
// platform and governed packages (and contextreg the context runtime). Only cmd/ composes contexts.
package kernel_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var contexts = []string{"ontology", "lifecycle", "contextreg", "policy", "registry", "governance", "evidence"}

func TestContextsAreIsolated(t *testing.T) {
	isContext := map[string]bool{}
	for _, c := range contexts {
		isContext[c] = true
	}
	for _, c := range append(contexts, "platform", "governed") {
		err := filepath.WalkDir(c, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				rest, ok := strings.CutPrefix(p, "ucos.dev/ri/kernel/")
				if !ok {
					continue
				}
				target := strings.SplitN(rest, "/", 2)[0]
				if isContext[target] && target != c {
					t.Errorf("%s: context %s must not import context %s (use governed ports)", path, c, target)
				}
				if (c == "platform" || c == "governed") && isContext[target] {
					t.Errorf("%s: shared package %s must not import a context", path, c)
				}
				if c == "platform" && target == "governed" {
					t.Errorf("%s: platform must not depend on governed", path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
