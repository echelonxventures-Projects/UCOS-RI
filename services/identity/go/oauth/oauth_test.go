package oauth

import (
	"testing"
	"time"
)

func TestScopeIntersectionOnlyNarrows(t *testing.T) {
	got := intersect("ucos:party:write ucos:party:read bogus ucos:billing:write", []string{"ucos:party:read", "ucos:billing:write"})
	if len(got) != 2 || got[0] != "ucos:party:read" || got[1] != "ucos:billing:write" {
		t.Fatalf("%v", got)
	}
	if len(intersect("ucos:party:read", nil)) != 0 {
		t.Fatal("nothing allowed → nothing granted")
	}
}

func TestLifetimeCappedAtTenMinutes(t *testing.T) {
	for in, want := range map[string]time.Duration{"PT10M": 10 * time.Minute, "PT5M": 5 * time.Minute, "PT1H": 10 * time.Minute, "PT30S": 30 * time.Second} {
		if d, ok := isoMinutes(in); !ok || d != want {
			t.Errorf("%s → %v %v, want %v", in, d, ok, want)
		}
	}
	if _, ok := isoMinutes("P1D"); ok {
		t.Error("only PT durations are access-token lifetimes")
	}
}

func TestActDepth(t *testing.T) {
	if depth(nil) != 0 || depth(map[string]any{"sub": "a"}) != 1 || depth(map[string]any{"sub": "a", "act": map[string]any{"sub": "b"}}) != 2 {
		t.Fatal("depth counts nested act claims")
	}
}

func TestPKCE(t *testing.T) { // RFC 7636 Appendix B
	if pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatal("S256 challenge mismatch")
	}
}
