package inv

// Exported access to the exact-quantity helpers for the sibling supply contexts (DOM-AVL). Inventory is the
// foundational supply context and owns the quantity contract (UCOS-L002: exact decimals, never binary
// floats); availability computes ATP from inventory positions in the same terms (CIC-011-006 §2).

import (
	"math/big"
	"time"
)

// ParseQ parses a non-negative decimal string into an exact rational.
func ParseQ(s string) (*big.Rat, error) { return parseQ(s) }

// ParseSQ parses a signed decimal.
func ParseSQ(s string) (*big.Rat, error) { return parseSQ(s) }

// FormatQ renders a rational as a decimal string at the storage scale.
func FormatQ(r *big.Rat) string { return formatQ(r) }

// IDOf accepts a ULID or a URN and returns the ULID part.
func IDOf(ref string) string { return idOf(ref) }

// ParseDuration parses the ISO 8601 duration subset the pack uses.
func ParseDuration(s string) (time.Duration, error) { return parseDuration(s) }
