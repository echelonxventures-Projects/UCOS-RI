// Architecture test (CR-001-001-01): commerce contexts never import each other; they share only platform modules.
// Only cmd/ composes contexts. It also enforces UCOS-L001 (CR-COB-04): no ucos.std type names in context code.
package commerce_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var contexts = []string{"cob"}

func TestContextsAreIsolated(t *testing.T) {
	for _, c := range contexts {
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
				if rest, ok := strings.CutPrefix(p, "ucos.dev/ri/commerce/"); ok && strings.SplitN(rest, "/", 2)[0] != c {
					t.Errorf("%s: context %s must not import %s (use ports wired in cmd/)", path, c, p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestNoTypeNameLiterals is CR-COB-04 / UCOS-L001: context code never branches on concrete pack type names.
func TestNoTypeNameLiterals(t *testing.T) {
	names := regexp.MustCompile(`"(Product|Service|Subscription|Membership|License|Plan|Bundle|Package|Asset|Experience|Capability|DigitalGood|PhysicalGood)"`)
	for _, c := range contexts {
		_ = filepath.WalkDir(c, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, _ := os.ReadFile(path)
			if m := names.Find(src); m != nil {
				t.Errorf("%s: type-name literal %s (UCOS-L001)", path, m)
			}
			return nil
		})
	}
}
