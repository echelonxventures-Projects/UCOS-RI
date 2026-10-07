package inv

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Quantity math is exact: quantities are decimal strings (UCOS-L002 forbids binary floats), stored as
// numeric(38,9) and handled in Go as big.Rat. The storage scale is 9 (matches the column); a value needing
// more places is refused rather than silently rounded.

// scale is the maximum number of decimal places carried (positions/movements numeric(38,9)).
const scale = 9

var scaleRat = new(big.Rat).SetFrac(new(big.Int).Exp(big.NewInt(10), big.NewInt(scale), nil), big.NewInt(1))

// parseQ parses a non-negative decimal string into an exact rational. Exponent notation is refused: the
// decimal contract is plain decimal (UCOS-L002).
func parseQ(s string) (*big.Rat, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("quantity is required")
	}
	if strings.ContainsAny(s, "eE") {
		return nil, fmt.Errorf("quantity %q must be a plain decimal", s)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("quantity %q is not a decimal", s)
	}
	if r.Sign() < 0 {
		return nil, fmt.Errorf("quantity %q must not be negative", s)
	}
	return r, nil
}

// parseSQ parses a signed decimal (movements may carry negative adjustments).
func parseSQ(s string) (*big.Rat, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("quantity is required")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("quantity %q is not a decimal", s)
	}
	return r, nil
}

// formatQ renders a rational as a decimal string at the storage scale (9 places, matching numeric(38,9)),
// rounding half to even. Values needing more places are rounded rather than rejected: the storage column
// rounds identically, so Go arithmetic and the ledger stay in step (CR-INV-02).
func formatQ(r *big.Rat) string {
	return r.FloatString(scale)
}

// ratOfInt makes an integer rational.
func ratOfInt(i *big.Int) *big.Rat { return new(big.Rat).SetFrac(i, big.NewInt(1)) }

// sub returns a - b.
func sub(a, b *big.Rat) *big.Rat { return new(big.Rat).Sub(a, b) }

// add returns a + b.
func add(a, b *big.Rat) *big.Rat { return new(big.Rat).Add(a, b) }

// nonNeg reports whether a >= 0.
func nonNeg(a *big.Rat) bool { return a.Sign() >= 0 }

// ---------------------------------------------------------------- ids and refs

// idOf accepts a ULID or a URN and returns the ULID part.
func idOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

// lotOf normalizes a nullable lot reference to the position key form ('' = no lot).
func lotOf(lot *string) string {
	if lot == nil {
		return ""
	}
	return strings.TrimSpace(*lot)
}

// Movement is a ledger entry as served by GetMovementHistory.
type Movement struct {
	MovementID     string   `json:"movementId"`
	Type           string   `json:"type"`
	ObjectRef      string   `json:"objectRef"`
	NodeRef        string   `json:"nodeRef"`
	Quantity       string   `json:"quantity"`
	FromStatus     *string  `json:"fromStatus"`
	ToStatus       *string  `json:"toStatus"`
	LotRef         string   `json:"lotRef"`
	Serials        []string `json:"serials"`
	SourceDocument string   `json:"sourceDocument"`
	IdempotencyKey string   `json:"idempotencyKey"`
	ReasonCode     string   `json:"reasonCode"`
	OccurredAt     string   `json:"occurredAt"`
}

// Position is an InventoryPosition as served by GetPosition.
type Position struct {
	ObjectRef   string           `json:"objectRef"`
	NodeRef     string           `json:"nodeRef"`
	StockStatus string           `json:"stockStatus"`
	LotRef      string           `json:"lotRef"`
	OnHand      string           `json:"onHand"`
	Reserved    string           `json:"reserved"`
	SafetyStock string           `json:"safetyStock"`
	Available   string           `json:"available"` // onHand - reserved - safetyStock (DEC-INV-1, before oversell)
	Version     int64            `json:"version"`
	Lots        []map[string]any `json:"lots,omitempty"` // per-lot breakdown
}

// ReserveLine is one line of a reservation request.
type ReserveLine struct {
	ObjectRef string   `json:"objectRef"`
	NodeRef   string   `json:"nodeRef"`
	Quantity  string   `json:"quantity"`
	LotRef    *string  `json:"lotRef"`
	Serials   []string `json:"serials"`
}

// Reservation is the aggregate as served by GetReservation.
type Reservation struct {
	ID        string        `json:"id"`
	URN       string        `json:"urn"`
	SourceRef string        `json:"sourceRef"`
	Kind      string        `json:"kind"`
	Lines     []ReserveLine `json:"lines"`
	Status    string        `json:"status"`
	ExpiresAt *string       `json:"expiresAt"`
	Revision  int64         `json:"revision"`
}

// Pool is a CapacityPool.
type Pool struct {
	ID               string         `json:"id"`
	URN              string         `json:"urn"`
	ResourceRef      string         `json:"resourceRef"`
	Label            map[string]any `json:"label"`
	SlotDuration     string         `json:"slotDuration"`
	CapacityPerSlot  string         `json:"capacityPerSlot"`
	Timezone         string         `json:"timezone"`
	Exceptions       []any          `json:"exceptions"`
	Revision         int64          `json:"revision"`
}

// Slot is one capacity slot as served by GetCapacitySlots.
type Slot struct {
	SlotStart string `json:"slotStart"`
	Capacity  string `json:"capacity"`
	Booked    string `json:"booked"`
	Free      string `json:"free"`
}

// NodePort resolves a fulfillment node's kind (the nodeKind attribute of its FulfillmentNode object,
// DOM-COB) so that node policies (oversell allowance, negative on hand) apply (RUL-INV-4, INV-INV-1).
// Unreadable nodes fall back to the strictest policy: no oversell, no negative stock.
type NodePort interface {
	Kind(ctx context.Context, tenant, nodeRef string) (kind string, err error)
}
