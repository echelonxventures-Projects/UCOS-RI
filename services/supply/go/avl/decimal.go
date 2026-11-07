package avl

// Exact-quantity and id helpers, delegated to DOM-INV's decimal contract (UCOS-L002) so availability and
// inventory arithmetic stay in step: ATP is computed from inventory positions in the same terms
// (CIC-011-006 §2).

import (
	"math/big"
	"time"

	"ucos.dev/ri/supply/inv"
)

func parseQ(s string) (*big.Rat, error) { return inv.ParseQ(s) }

func parseSQ(s string) (*big.Rat, error) { return inv.ParseSQ(s) }

func formatQ(r *big.Rat) string { return inv.FormatQ(r) }

func idOf(ref string) string { return inv.IDOf(ref) }

func parseDuration(s string) (time.Duration, error) { return inv.ParseDuration(s) }
