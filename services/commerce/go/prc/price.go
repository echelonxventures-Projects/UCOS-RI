package prc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

// LineRequest is a PriceLineRequest (CIC-011-004 §1).
type LineRequest struct {
	LineID    string `json:"lineId"`
	ObjectRef string `json:"objectRef"`
	Quantity  struct {
		Value string `json:"value"`
		Unit  string `json:"unit"`
	} `json:"quantity"`
	Usage []struct {
		Meter    string `json:"meter"`
		Quantity string `json:"quantity"`
	} `json:"usage"`
	ContractRef string `json:"contractRef"`
}

// Request is a PriceRequest.
type Request struct {
	Context map[string]any `json:"context"`
	AsOf    *time.Time     `json:"asOf"`
	Lines   []LineRequest  `json:"lines"`
	Options struct {
		Explain bool `json:"explain"`
	} `json:"options"`
}

// Result is a PriceResult.
type Result struct {
	Lines             []PricedLine   `json:"lines"`
	Totals            map[string]any `json:"totals"`
	Currency          string         `json:"currency"`
	PricingSnapshotID string         `json:"pricingSnapshotId"`
	SnapshotVersion   int64          `json:"snapshotVersion"`
	AsOf              time.Time      `json:"asOf"`
	ContextDigest     string         `json:"contextDigest"`
	Trace             []any          `json:"trace,omitempty"`
}

const instantFmt = "2006-01-02T15:04:05.000Z"

// visible loads the entries for subjects visible at snapshot version v (published rows whose snapshot range holds v).
func (s *PRC) visible(ctx context.Context, tx pgx.Tx, subjects []string, v int64) ([]Entry, error) {
	rows, err := tx.Query(ctx, `SELECT `+entryCols+` FROM ucos_pricing.price_entries e JOIN ucos_pricing.price_lists l
		ON l.tenant_id = e.tenant_id AND l.id = e.list_id
		WHERE e.tenant_id = current_setting('ucos.tenant_id')::uuid AND e.subject = ANY($1)
		  AND e.snapshot_from IS NOT NULL AND e.snapshot_from <= $2 AND (e.snapshot_to IS NULL OR e.snapshot_to > $2)`, subjects, v)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Entry, error) { return scanEntry(r) })
}

func candidate(e Entry) ctxrt.Candidate {
	raw, _ := json.Marshal(map[string]any{"entryId": e.EntryID, "listId": e.ListID})
	var to *string
	if e.ValidTo != nil {
		x := e.ValidTo.UTC().Format(instantFmt)
		to = &x
	}
	return ctxrt.Candidate{ID: e.EntryID + "#" + fmt.Sprint(e.rowSeq), Scope: append(append([]ctxrt.Constraint{}, e.listScope...), e.Scope...),
		ValidFrom: e.ValidFrom.UTC().Format(instantFmt), ValidTo: to, Priority: int64(e.listPrio)*1_000_000 + int64(e.Priority), Value: raw}
}

// Price implements DEC-PRC-1 (CIC-011-004 §3) at the current snapshot; the request is recorded for replay.
func (s *PRC) Price(ctx context.Context, p svc.Principal, req Request) (Result, error) {
	return s.price(ctx, p, req, -1, true)
}

// Replay implements ReplayPrice: re-price the recorded request at its recorded snapshot version and asOf.
func (s *PRC) Replay(ctx context.Context, p svc.Principal, snapshotID string) (Result, error) {
	var v int64
	var asOf time.Time
	var raw []byte
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT snapshot_version, as_of, request FROM ucos_pricing.pricing_snapshots
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND snapshot_id = $1`, snapshotID).Scan(&v, &asOf, &raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{}, svc.Errf(404, "E-PRC-UNKNOWN-SNAPSHOT", "pricing snapshot %s is not recorded", snapshotID)
	}
	if err != nil {
		return Result{}, err
	}
	var req Request
	decode(raw, &req)
	t := asOf.UTC()
	req.AsOf = &t
	return s.price(ctx, p, req, v, false)
}

func (s *PRC) price(ctx context.Context, p svc.Principal, req Request, version int64, record bool) (Result, error) {
	if len(req.Lines) == 0 {
		return Result{}, svc.Errf(422, "E-API-VALIDATION", "a price request needs at least one line")
	}
	world, err := s.Meta.World(ctx, p.TenantSlug)
	if err != nil {
		return Result{}, err
	}
	var cfg ctxrt.Config
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.EntryResolution, &cfg); err != nil {
		return Result{}, err
	}
	var rounding Rounding
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Rounding, &rounding); err != nil {
		return Result{}, err
	}
	asOf := s.Clock.Now().UTC()
	if req.AsOf != nil {
		asOf = req.AsOf.UTC()
	}
	explicit := map[string]any{}
	for k, v := range req.Context {
		explicit[k] = v
	}
	principal := map[string]any{"tenant": p.TenantSlug, "party": p.Party}
	if p.Organization != "" {
		principal["organization"] = p.Organization
	}
	baseAsm := ctxrt.Assemble(world, explicit, principal, nil, asOf.Format(instantFmt), 60)
	if baseAsm.Status != "ok" {
		return Result{}, svc.Errf(422, "E-CTX-ASSEMBLY-FAILED", "context assembly failed")
	}
	currency, _ := baseAsm.Vector["currency"].Value.(string)
	if currency == "" {
		return Result{}, svc.Errf(422, "E-PRC-CURRENCY-REQUIRED", "the context must name a currency (CIC-011-004 §3)")
	}
	res := Result{Currency: currency, AsOf: asOf, ContextDigest: *baseAsm.Digest}
	err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if version < 0 {
			if version, err = s.currentSnapshot(ctx, tx); err != nil {
				return err
			}
		}
		res.SnapshotVersion = version
		priced := map[string]*big.Rat{} // exact line totals for percentage-of
		pending := append([]LineRequest{}, req.Lines...)
		out := map[string]PricedLine{}
		for pass := 0; len(pending) > 0 && pass <= len(req.Lines); pass++ {
			var waiting []LineRequest
			for _, line := range pending {
				pl, trace, err := s.priceLine(ctx, tx, p, line, explicit, principal, world, cfg, rounding, currency, asOf, version, priced)
				if errors.Is(err, errWaiting) {
					waiting = append(waiting, line)
					continue
				}
				if err != nil {
					return err
				}
				out[line.LineID] = pl
				if req.Options.Explain {
					res.Trace = append(res.Trace, trace)
				}
			}
			if len(waiting) == len(pending) {
				return svc.Errf(422, "E-PRC-INVALID-BASE", "percentage-of bases form a cycle or reference no line of this request")
			}
			pending = waiting
		}
		for _, l := range req.Lines {
			res.Lines = append(res.Lines, out[l.LineID])
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	var totals []Money
	for _, l := range res.Lines {
		totals = append(totals, l.Total)
	}
	total := SumMoney(currency, totals...)
	if rounding.Stage == "total" {
		r, _ := total.Rat()
		rounded, err := Round(r, MinorUnits(currency), rounding.Mode)
		if err != nil {
			return Result{}, err
		}
		total = MoneyAt(rounded, currency, MinorUnits(currency))
	}
	res.Totals = map[string]any{"subtotal": total, "discountTotal": Money{AmountMinor: "0", Currency: currency, Scale: MinorUnits(currency)},
		"taxTotal": Money{AmountMinor: "0", Currency: currency, Scale: MinorUnits(currency)}, "total": total}
	reqRaw, _ := json.Marshal(map[string]any{"context": req.Context, "lines": req.Lines})
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s|%s|%s", p.TenantSlug, version, res.ContextDigest, asOf.Format(instantFmt), reqRaw)))
	res.PricingSnapshotID = hex.EncodeToString(sum[:])
	if record {
		err = s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
			stored, _ := json.Marshal(map[string]any{"context": req.Context, "lines": req.Lines})
			_, err := tx.Exec(ctx, `INSERT INTO ucos_pricing.pricing_snapshots (tenant_id, snapshot_id, snapshot_version, as_of, request, created_at)
				VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, now()) ON CONFLICT DO NOTHING`,
				res.PricingSnapshotID, version, asOf, stored)
			return err
		})
	}
	return res, err
}

var errWaiting = errors.New("waiting for a percentage-of base")

func (s *PRC) priceLine(ctx context.Context, tx pgx.Tx, p svc.Principal, line LineRequest, explicit, principal map[string]any,
	world *ctxrt.World, cfg ctxrt.Config, rounding Rounding, currency string, asOf time.Time, version int64,
	priced map[string]*big.Rat) (PricedLine, map[string]any, error) {
	qty, err := ParseQuantity(line.Quantity.Value)
	if err != nil {
		return PricedLine{}, nil, svc.Errf(422, "E-API-VALIDATION", "line %s: %v", line.LineID, err)
	}
	exists, lineage, err := s.Objects.Lineage(ctx, p, line.ObjectRef)
	if err != nil {
		return PricedLine{}, nil, err
	}
	if !exists {
		return PricedLine{}, nil, svc.Errf(422, "E-PRC-UNKNOWN-OBJECT", "line %s: %s does not exist", line.LineID, line.ObjectRef)
	}
	ctxIn := map[string]any{}
	for k, v := range explicit {
		ctxIn[k] = v
	}
	if line.ContractRef != "" {
		ctxIn["contract"] = line.ContractRef
	}
	asm := ctxrt.Assemble(world, ctxIn, principal, nil, asOf.Format(instantFmt), 60)
	values := map[string]any{}
	for k, slot := range asm.Vector {
		values[k] = slot.Value
	}
	vec := ctxrt.Context{Values: values, AsOf: asOf.Format(instantFmt), CacheGranularitySeconds: 60}
	entries, err := s.visible(ctx, tx, append([]string{line.ObjectRef}, lineage...), version)
	if err != nil {
		return PricedLine{}, nil, err
	}
	byKey := map[string][]Entry{} // subject|chargeType -> entries in the request currency
	charges := map[string]bool{}
	for _, e := range entries {
		if e.Currency != currency {
			continue // conversion is policy pricing.conversion.allowed; ucos.std disallows it
		}
		byKey[e.Subject+"|"+e.ChargeType] = append(byKey[e.Subject+"|"+e.ChargeType], e)
		charges[e.ChargeType] = true
	}
	trace := map[string]any{"lineId": line.LineID, "resolutions": []any{}}
	var raw []Component
	chargeList := make([]string, 0, len(charges))
	for c := range charges {
		chargeList = append(chargeList, c)
	}
	sort.Strings(chargeList)
	for _, ct := range chargeList {
		// RUL-PRC-2: object-level entries beat type-level ones; types are tried nearest first.
		var chosen *Entry
		for _, subject := range append([]string{line.ObjectRef}, lineage...) {
			cands := byKey[subject+"|"+ct]
			if len(cands) == 0 {
				continue
			}
			cs := make([]ctxrt.Candidate, len(cands))
			for i, e := range cands {
				cs[i] = candidate(e)
			}
			r := ctxrt.Resolve(world, "price-entry", cs, vec, cfg)
			trace["resolutions"] = append(trace["resolutions"].([]any), map[string]any{"chargeType": ct, "subject": subject, "resolution": r.Canonical()})
			if r.Status == "error" {
				return PricedLine{}, nil, svc.Errf(422, "E-PRC-AMBIGUOUS", "line %s: equally specific %s prices for %s (RUL-PRC-1)", line.LineID, ct, subject)
			}
			if r.Status == "one" && len(r.Selected) == 1 {
				for i := range cands {
					if candidate(cands[i]).ID == r.Selected[0] {
						chosen = &cands[i]
					}
				}
				break
			}
		}
		if chosen == nil {
			continue
		}
		q := qty
		if ct == "usage" {
			q = nil
			for _, u := range line.Usage {
				if chosen.MeterRef != nil && u.Meter == *chosen.MeterRef {
					if q, err = ParseQuantity(u.Quantity); err != nil {
						return PricedLine{}, nil, svc.Errf(422, "E-API-VALIDATION", "usage %s: %v", u.Meter, err)
					}
				}
			}
			if q == nil {
				continue // no usage reported for this meter
			}
		}
		amount, detail, err := Evaluate(chosen.Model, Inputs{Quantity: q, Currency: currency,
			BaseOf: func(ref string) (*big.Rat, bool) { x, ok := priced[ref]; return x, ok },
			Formula: func(expr string) (*big.Int, error) {
				view, err := s.Objects.View(ctx, p, line.ObjectRef, explicit)
				if err != nil {
					return nil, err
				}
				n, ok := new(big.Int).SetString(q.FloatString(0), 10)
				if !ok || new(big.Rat).SetInt(n).Cmp(q) != 0 {
					return nil, fmt.Errorf("formula models need an integer quantity")
				}
				out, err := s.Meta.Engine.EvalCEL(expr, map[string]any{"quantity": n.Int64(), "object": view, "ctx": values,
					"line": map[string]any{"lineId": line.LineID, "objectRef": line.ObjectRef}})
				if err != nil {
					return nil, err
				}
				v, ok := toInt(out)
				if !ok {
					return nil, fmt.Errorf("formula must return an integer amount in minor units")
				}
				return v, nil
			}})
		if err != nil {
			if svc.Str(chosen.Model, "kind") == "percentage-of" && priced[svc.Str(chosen.Model, "baseRef")] == nil {
				return PricedLine{}, nil, errWaiting
			}
			return PricedLine{}, nil, svc.Errf(422, "E-PRC-MODEL-FAILED", "line %s: %v", line.LineID, err)
		}
		c := NewComponent("base", ct, "urn:ucos:"+p.TenantSlug+":pricelist:"+chosen.ListID+"#"+chosen.EntryID, "LIST", amount, detail)
		c.Recurrence = chosen.Recurrence
		raw = append(raw, c)
	}
	if len(raw) == 0 {
		return PricedLine{}, nil, svc.Errf(422, "E-PRC-NO-PRICE", "line %s: no price for %s in %s (CIC-011-004 §3)", line.LineID, line.ObjectRef, currency)
	}
	pl := PricedLine{LineID: line.LineID, ObjectRef: line.ObjectRef, Recurring: []Component{}, UsageRating: []Component{}}
	if err := Finish(&pl, raw, currency, rounding); err != nil {
		return PricedLine{}, nil, err
	}
	for _, c := range pl.Components {
		switch c.ChargeType {
		case "recurring":
			pl.Recurring = append(pl.Recurring, c)
		case "usage":
			pl.UsageRating = append(pl.UsageRating, c)
		}
	}
	exact, _ := pl.Total.Rat()
	priced[line.LineID] = exact
	return pl, trace, nil
}
