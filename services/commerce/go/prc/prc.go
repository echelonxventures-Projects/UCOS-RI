package prc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ucos.dev/ri/contextruntime/ctxrt"
	"ucos.dev/ri/svckit/svc"
)

// Objects is the DOM-COB port pricing needs (wired by the composition root).
type Objects interface {
	// Lineage returns whether the object exists and its type linearization (nearest type first).
	Lineage(ctx context.Context, p svc.Principal, ref string) (bool, []string, error)
	// View returns the object's resolved attribute values in the explicit context (formula models).
	View(ctx context.Context, p svc.Principal, ref string, explicit map[string]any) (map[string]any, error)
}

// Config names the policies pricing reads (composition-root configuration).
type Config struct {
	EntryResolution string // ResolutionConfig of fact kind price-entry
	Rounding        string // pricing.rounding
	Approval        string // pricing.approval (approval plan by change magnitude)
	ChargeTypes     []string
}

// PRC implements DOM-PRC.
type PRC struct {
	DB      *svc.DB
	Meta    *svc.Metadata
	Clock   *svc.Clock
	Source  string
	Objects Objects
	Cfg     Config
}

// ---------------------------------------------------------------- price lists

// PriceList is the aggregate as served.
type PriceList struct {
	ID            string             `json:"id"`
	URN           string             `json:"urn"`
	Code          string             `json:"code"`
	Label         map[string]any     `json:"label"`
	Currency      string             `json:"currency"`
	MultiCurrency bool               `json:"multiCurrency"`
	Scope         []ctxrt.Constraint `json:"scope"`
	Priority      int                `json:"priority"`
	ValidFrom     time.Time          `json:"validFrom"`
	ValidTo       *time.Time         `json:"validTo"`
	BasedOn       *string            `json:"basedOn"`
	Derivation    *string            `json:"derivation"`
	State         string             `json:"lifecycleState"`
	Version       int                `json:"version"`
	EffectiveAt   *time.Time         `json:"effectiveAt"`
	Author        string             `json:"author"`
	Approvals     []map[string]any   `json:"approvals"`
	Plan          []Stage            `json:"approvalPlan"`
	Revision      int64              `json:"revision"`
}

// Stage is one approval stage.
type Stage struct {
	ApproverRoles []string `json:"approverRoles"`
	Quorum        int      `json:"quorum"`
}

// Entry is a PriceEntry as served.
type Entry struct {
	EntryID     string             `json:"entryId"`
	ListID      string             `json:"listId"`
	SubjectKind string             `json:"subjectKind"`
	Subject     string             `json:"subject"`
	ChargeType  string             `json:"chargeType"`
	Model       map[string]any     `json:"priceModel"`
	Scope       []ctxrt.Constraint `json:"scope"`
	Priority    int                `json:"priority"`
	Currency    string             `json:"currency"`
	Recurrence  map[string]any     `json:"recurrence,omitempty"`
	MeterRef    *string            `json:"meterRef,omitempty"`
	ValidFrom   time.Time          `json:"validFrom"`
	ValidTo     *time.Time         `json:"validTo"`
	rowSeq      int
	listScope   []ctxrt.Constraint
	listPrio    int
}

func decode(raw []byte, out any) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(out)
}

const listCols = `id, urn, code, label, currency, multi_currency, scope, priority, valid_from, valid_to, based_on, derivation, state,
	version, effective_at, author, approvals, plan, revision`

func (s *PRC) scanList(row pgx.Row) (PriceList, error) {
	var l PriceList
	var label, scope, approvals, plan []byte
	err := row.Scan(&l.ID, &l.URN, &l.Code, &label, &l.Currency, &l.MultiCurrency, &scope, &l.Priority, &l.ValidFrom, &l.ValidTo,
		&l.BasedOn, &l.Derivation, &l.State, &l.Version, &l.EffectiveAt, &l.Author, &approvals, &plan, &l.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, svc.ErrNotFound
	}
	if err != nil {
		return l, err
	}
	l.ID = strings.TrimSpace(l.ID)
	decode(label, &l.Label)
	decode(scope, &l.Scope)
	decode(approvals, &l.Approvals)
	decode(plan, &l.Plan)
	if l.Scope == nil {
		l.Scope = []ctxrt.Constraint{}
	}
	if l.Approvals == nil {
		l.Approvals = []map[string]any{}
	}
	if l.State == "scheduled" && l.EffectiveAt != nil && !s.Clock.Now().Before(*l.EffectiveAt) {
		l.State = "published" // the scheduled -> published trigger, evaluated at read (no scheduler needed)
	}
	return l, nil
}

func idOf(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func (s *PRC) loadList(ctx context.Context, tx pgx.Tx, ref string, lock bool) (PriceList, error) {
	q := `SELECT ` + listCols + ` FROM ucos_pricing.price_lists WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`
	if lock {
		q += " FOR UPDATE"
	}
	return s.scanList(tx.QueryRow(ctx, q, idOf(ref)))
}

func (s *PRC) event(ctx context.Context, tx pgx.Tx, p svc.Principal, l PriceList, typ string, payload map[string]any) error {
	seq, err := svc.NextSequence(ctx, tx, Schema, l.ID)
	if err != nil {
		return err
	}
	return svc.Append(ctx, tx, Schema, s.Source, s.Clock.Now(), svc.Event{Type: typ, AggregateID: l.ID, Sequence: seq,
		Payload: payload, CorrelationID: svc.CorrelationID(ctx), Principal: p.Party, TenantSlug: p.TenantSlug, Subject: l.URN})
}

func scopeDigest(scope []ctxrt.Constraint) string {
	type c struct {
		D string `json:"d"`
		O string `json:"o"`
		V []any  `json:"v"`
	}
	norm := make([]c, 0, len(scope))
	for _, k := range scope {
		vals := append([]any{}, k.Values...)
		sort.Slice(vals, func(i, j int) bool { return fmt.Sprint(vals[i]) < fmt.Sprint(vals[j]) })
		norm = append(norm, c{k.Dimension, k.Op, vals})
	}
	sort.Slice(norm, func(i, j int) bool { return fmt.Sprint(norm[i]) < fmt.Sprint(norm[j]) })
	raw, _ := json.Marshal(norm)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ListInput is the CreatePriceList input.
type ListInput struct {
	Code          string             `json:"code"`
	Label         map[string]any     `json:"label"`
	Currency      string             `json:"currency"`
	MultiCurrency bool               `json:"multiCurrency"`
	Scope         []ctxrt.Constraint `json:"scope"`
	Priority      int                `json:"priority"`
	ValidFrom     *time.Time         `json:"validFrom"`
	ValidTo       *time.Time         `json:"validTo"`
	BasedOn       *string            `json:"basedOn"`
	Derivation    *string            `json:"derivation"`
}

// CreateList implements CreatePriceList. A list's version is one more than the highest version of its code.
func (s *PRC) CreateList(ctx context.Context, p svc.Principal, in ListInput) (PriceList, error) {
	if in.Code == "" || len(in.Currency) < 3 {
		return PriceList{}, svc.Errf(422, "E-API-VALIDATION", "code and currency are required")
	}
	if in.Scope == nil {
		in.Scope = []ctxrt.Constraint{}
	}
	if in.Label == nil {
		in.Label = map[string]any{"default": in.Code}
	}
	from := s.Clock.Now().UTC()
	if in.ValidFrom != nil {
		from = in.ValidFrom.UTC()
	}
	if in.ValidTo != nil && !in.ValidTo.After(from) {
		return PriceList{}, svc.Errf(422, "E-API-VALIDATION", "validTo must be after validFrom")
	}
	var out PriceList
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_pricing.code:' || current_setting('ucos.tenant_id') || $1))`, in.Code); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) + 1 FROM ucos_pricing.price_lists
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND code = $1`, in.Code).Scan(&version); err != nil {
			return err
		}
		id := svc.NewULID()
		label, _ := json.Marshal(in.Label)
		scope, _ := json.Marshal(in.Scope)
		if _, err := tx.Exec(ctx, `INSERT INTO ucos_pricing.price_lists (tenant_id, id, urn, code, label, currency, multi_currency, scope,
			priority, valid_from, valid_to, based_on, derivation, state, version, author, approvals, revision, created_at)
			VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'draft', $13, $14, '[]', 1, now())`,
			id, "urn:ucos:"+p.TenantSlug+":pricelist:"+id, in.Code, label, in.Currency, in.MultiCurrency, scope, in.Priority, from,
			in.ValidTo, in.BasedOn, in.Derivation, version, p.Party); err != nil {
			return err
		}
		var err error
		if out, err = s.loadList(ctx, tx, id, false); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out, "ucos.pricing.price-list.created.v1", map[string]any{"id": out.URN, "code": out.Code,
			"currency": out.Currency, "scope": out.Scope, "validFrom": out.ValidFrom, "validTo": out.ValidTo})
	})
	return out, err
}

// GetList implements GetPriceList.
func (s *PRC) GetList(ctx context.Context, p svc.Principal, ref string) (PriceList, error) {
	var l PriceList
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		var err error
		l, err = s.loadList(ctx, tx, ref, false)
		return err
	})
	return l, err
}

// FindLists implements FindPriceLists.
func (s *PRC) FindLists(ctx context.Context, p svc.Principal, state, currency, code string) ([]PriceList, error) {
	out := []PriceList{}
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+listCols+` FROM ucos_pricing.price_lists WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND ($1 = '' OR currency = $1) AND ($2 = '' OR code = $2) ORDER BY code, version LIMIT 500`, currency, code)
		if err != nil {
			return err
		}
		ls, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (PriceList, error) { return s.scanList(r) })
		for _, l := range ls {
			if state == "" || l.State == state {
				out = append(out, l)
			}
		}
		return err
	})
	return out, err
}

// EntryInput is one AddPriceEntries element.
type EntryInput struct {
	Subject    string             `json:"subject"` // object URN, or a type name / type URN
	ChargeType string             `json:"chargeType"`
	Model      map[string]any     `json:"priceModel"`
	Scope      []ctxrt.Constraint `json:"scope"`
	Priority   int                `json:"priority"`
	Currency   string             `json:"currency"`
	Recurrence map[string]any     `json:"recurrence"`
	MeterRef   *string            `json:"meterRef"`
	ValidFrom  *time.Time         `json:"validFrom"`
	ValidTo    *time.Time         `json:"validTo"`
}

func (s *PRC) checkRevision(l PriceList, expected int64) error {
	if expected <= 0 {
		return svc.Errf(428, "E-API-PRECONDITION-REQUIRED", "If-Match with the current revision is required")
	}
	if expected != l.Revision {
		return svc.Errf(412, "E-API-PRECONDITION-FAILED", "revision is %d, not %d", l.Revision, expected)
	}
	return nil
}

func (s *PRC) bump(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_lists SET revision = revision + 1
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, id)
	return err
}

func overlaps(af time.Time, at *time.Time, bf time.Time, bt *time.Time) bool {
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	ae, be := far, far
	if at != nil {
		ae = *at
	}
	if bt != nil {
		be = *bt
	}
	return af.Before(be) && bf.Before(ae)
}

// AddEntries implements AddPriceEntries (list in draft or in-review; INV-PRC-1, 2, 4, 5).
func (s *PRC) AddEntries(ctx context.Context, p svc.Principal, ref string, expected int64, entries []EntryInput) (PriceList, []Entry, error) {
	if len(entries) == 0 || len(entries) > 10000 {
		return PriceList{}, nil, svc.Errf(422, "E-API-VALIDATION", "1..10000 entries per call")
	}
	var list PriceList
	var added []Entry
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		l, err := s.loadList(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		if err := s.checkRevision(l, expected); err != nil {
			return err
		}
		if l.State != "draft" && l.State != "in-review" {
			return svc.Errf(409, "E-PRC-LIST-NOT-EDITABLE", "entries of a %s list are immutable (INV-PRC-3)", l.State)
		}
		existing, err := s.entries(ctx, tx, l.ID, true)
		if err != nil {
			return err
		}
		for i, in := range entries {
			e, err := s.validateEntry(ctx, p, l, in)
			if err != nil {
				return &svc.Error{Status: 422, Code: codeOf(err, "E-PRC-INVALID-ENTRY"), Detail: fmt.Sprintf("entry %d: %v", i, msgOf(err))}
			}
			for _, x := range existing {
				if x.Subject == e.Subject && x.ChargeType == e.ChargeType && scopeDigest(x.Scope) == scopeDigest(e.Scope) &&
					x.Currency == e.Currency && overlaps(x.ValidFrom, x.ValidTo, e.ValidFrom, e.ValidTo) {
					return svc.Errf(409, "E-PRC-OVERLAP", "entry %d overlaps entry %s for the same subject, charge type and scope (INV-PRC-2)", i, x.EntryID)
				}
			}
			if err := s.insertEntry(ctx, tx, l, e, 1, nil); err != nil {
				return err
			}
			existing = append(existing, e)
			added = append(added, e)
		}
		if err := s.bump(ctx, tx, l.ID); err != nil {
			return err
		}
		if list, err = s.loadList(ctx, tx, l.ID, false); err != nil {
			return err
		}
		summary := make([]map[string]any, 0, len(added))
		for _, e := range added {
			summary = append(summary, map[string]any{"entryId": e.EntryID, "subject": e.Subject, "chargeType": e.ChargeType})
		}
		return s.event(ctx, tx, p, list, "ucos.pricing.price-list.entries-added.v1", map[string]any{"id": list.URN, "revision": list.Revision,
			"entries": summary})
	})
	return list, added, err
}

func codeOf(err error, def string) string {
	var pe *svc.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return def
}

func msgOf(err error) string {
	var pe *svc.Error
	if errors.As(err, &pe) {
		return pe.Detail
	}
	return err.Error()
}

func (s *PRC) validateEntry(ctx context.Context, p svc.Principal, l PriceList, in EntryInput) (Entry, error) {
	e := Entry{EntryID: svc.NewULID(), ListID: l.ID, ChargeType: in.ChargeType, Model: in.Model, Scope: in.Scope, Priority: in.Priority,
		Currency: l.Currency, Recurrence: in.Recurrence, MeterRef: in.MeterRef, ValidFrom: l.ValidFrom, ValidTo: l.ValidTo}
	if e.Scope == nil {
		e.Scope = []ctxrt.Constraint{}
	}
	ok := false
	for _, c := range s.Cfg.ChargeTypes {
		ok = ok || c == in.ChargeType
	}
	if !ok {
		return e, fmt.Errorf("chargeType must be one of %v", s.Cfg.ChargeTypes)
	}
	if l.MultiCurrency {
		if in.Currency == "" {
			return e, fmt.Errorf("entries of a multi-currency list declare their currency (INV-PRC-1)")
		}
		e.Currency = in.Currency
	} else if in.Currency != "" && in.Currency != l.Currency {
		return e, fmt.Errorf("entry currency %s differs from list currency %s (INV-PRC-1)", in.Currency, l.Currency)
	}
	if strings.HasPrefix(in.Subject, "urn:ucos:") && strings.Contains(in.Subject, ":co:") {
		exists, _, err := s.Objects.Lineage(ctx, p, in.Subject)
		if err != nil {
			return e, err
		}
		if !exists {
			return e, fmt.Errorf("subject %s does not exist", in.Subject)
		}
		e.SubjectKind, e.Subject = "object", in.Subject
	} else {
		def, err := s.Meta.ResolveType(ctx, p.TenantSlug, in.Subject)
		if err != nil {
			return e, err
		}
		e.SubjectKind, e.Subject = "type", def.Name
	}
	if in.ValidFrom != nil {
		e.ValidFrom = in.ValidFrom.UTC()
	}
	if in.ValidTo != nil {
		t := in.ValidTo.UTC()
		e.ValidTo = &t
	}
	if e.ValidTo != nil && !e.ValidTo.After(e.ValidFrom) {
		return e, fmt.Errorf("validTo must be after validFrom")
	}
	switch in.ChargeType {
	case "recurring":
		if svc.Str(in.Recurrence, "period") == "" {
			return e, fmt.Errorf("recurring entries need recurrence.period")
		}
	case "usage":
		if in.MeterRef == nil || *in.MeterRef == "" {
			return e, fmt.Errorf("usage entries need meterRef")
		}
	}
	compile := func(expr string) error {
		_, err := s.Meta.Engine.EvalCEL(expr, map[string]any{"quantity": 1, "line": map[string]any{}, "ctx": map[string]any{},
			"object": map[string]any{}})
		if err != nil && strings.Contains(err.Error(), "does not compile") {
			return fmt.Errorf("formula: %v (INV-PRC-5)", err)
		}
		return nil
	}
	if err := ValidateModel(in.Model, e.Currency, compile); err != nil {
		return e, err
	}
	return e, nil
}

func (s *PRC) insertEntry(ctx context.Context, tx pgx.Tx, l PriceList, e Entry, rowSeq int, snapshotFrom *int64) error {
	model, _ := json.Marshal(e.Model)
	scope, _ := json.Marshal(e.Scope)
	var rec any
	if e.Recurrence != nil {
		rec, _ = json.Marshal(e.Recurrence)
	}
	effective := append(append([]ctxrt.Constraint{}, l.Scope...), e.Scope...)
	_, err := tx.Exec(ctx, `INSERT INTO ucos_pricing.price_entries (tenant_id, list_id, entry_id, row_seq, subject_kind, subject, charge_type,
		model, scope, scope_digest, priority, currency, recurrence, meter_ref, valid_from, valid_to, snapshot_from)
		VALUES (current_setting('ucos.tenant_id')::uuid, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		l.ID, e.EntryID, rowSeq, e.SubjectKind, e.Subject, e.ChargeType, model, scope, scopeDigest(effective), e.Priority, e.Currency,
		rec, e.MeterRef, e.ValidFrom, e.ValidTo, snapshotFrom)
	return err
}

const entryCols = `e.entry_id, e.list_id, e.row_seq, e.subject_kind, e.subject, e.charge_type, e.model, e.scope, e.priority, e.currency,
	e.recurrence, e.meter_ref, e.valid_from, e.valid_to, l.scope, l.priority`

func scanEntry(r pgx.Row) (Entry, error) {
	var e Entry
	var model, scope, rec, lscope []byte
	err := r.Scan(&e.EntryID, &e.ListID, &e.rowSeq, &e.SubjectKind, &e.Subject, &e.ChargeType, &model, &scope, &e.Priority, &e.Currency,
		&rec, &e.MeterRef, &e.ValidFrom, &e.ValidTo, &lscope, &e.listPrio)
	e.EntryID, e.ListID = strings.TrimSpace(e.EntryID), strings.TrimSpace(e.ListID)
	decode(model, &e.Model)
	decode(scope, &e.Scope)
	decode(lscope, &e.listScope)
	if e.Scope == nil {
		e.Scope = []ctxrt.Constraint{}
	}
	if rec != nil {
		decode(rec, &e.Recurrence)
	}
	e.ValidFrom = e.ValidFrom.UTC()
	if e.ValidTo != nil {
		t := e.ValidTo.UTC()
		e.ValidTo = &t
	}
	return e, err
}

// entries returns a list's entries: draft rows (current=true for unpublished lists) or the current published rows.
func (s *PRC) entries(ctx context.Context, tx pgx.Tx, listID string, draft bool) ([]Entry, error) {
	cond := `e.snapshot_to IS NULL`
	if draft {
		cond = `e.snapshot_from IS NULL`
	}
	rows, err := tx.Query(ctx, `SELECT `+entryCols+` FROM ucos_pricing.price_entries e JOIN ucos_pricing.price_lists l
		ON l.tenant_id = e.tenant_id AND l.id = e.list_id
		WHERE e.tenant_id = current_setting('ucos.tenant_id')::uuid AND e.list_id = $1 AND `+cond+` ORDER BY e.entry_id`, listID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Entry, error) { return scanEntry(r) })
}

// FindEntries implements FindPriceEntries (a list's current entries, optionally for one subject).
func (s *PRC) FindEntries(ctx context.Context, p svc.Principal, listRef, subject string) ([]Entry, error) {
	var out []Entry
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		l, err := s.loadList(ctx, tx, listRef, false)
		if err != nil {
			return err
		}
		draft := l.State == "draft" || l.State == "in-review" || l.State == "approved"
		all, err := s.entries(ctx, tx, l.ID, draft)
		for _, e := range all {
			if subject == "" || e.Subject == subject {
				out = append(out, e)
			}
		}
		return err
	})
	if out == nil {
		out = []Entry{}
	}
	return out, err
}

// UpdateEntry implements UpdatePriceEntry (lists not yet published).
func (s *PRC) UpdateEntry(ctx context.Context, p svc.Principal, ref, entryID string, expected int64, patch EntryInput) (Entry, error) {
	var out Entry
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		l, err := s.loadList(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		if err := s.checkRevision(l, expected); err != nil {
			return err
		}
		if l.State != "draft" && l.State != "in-review" {
			return svc.Errf(409, "E-PRC-LIST-NOT-EDITABLE", "entries of a %s list are immutable (INV-PRC-3); end-date them instead", l.State)
		}
		cur, err := s.entries(ctx, tx, l.ID, true)
		if err != nil {
			return err
		}
		var e *Entry
		for i := range cur {
			if cur[i].EntryID == entryID {
				e = &cur[i]
			}
		}
		if e == nil {
			return svc.ErrNotFound
		}
		if patch.Model != nil {
			if err := ValidateModel(patch.Model, e.Currency, func(string) error { return nil }); err != nil {
				return svc.Errf(422, "E-PRC-INVALID-ENTRY", "%v", err)
			}
			e.Model = patch.Model
		}
		if patch.Scope != nil {
			e.Scope = patch.Scope
		}
		if patch.Priority != 0 {
			e.Priority = patch.Priority
		}
		if patch.ValidTo != nil {
			e.ValidTo = patch.ValidTo
		}
		model, _ := json.Marshal(e.Model)
		scope, _ := json.Marshal(e.Scope)
		effective := append(append([]ctxrt.Constraint{}, l.Scope...), e.Scope...)
		if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_entries SET model = $3, scope = $4, scope_digest = $5, priority = $6, valid_to = $7
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND list_id = $1 AND entry_id = $2 AND snapshot_from IS NULL`,
			l.ID, entryID, model, scope, scopeDigest(effective), e.Priority, e.ValidTo); err != nil {
			return err
		}
		if err := s.bump(ctx, tx, l.ID); err != nil {
			return err
		}
		out = *e
		return s.event(ctx, tx, p, l, "ucos.pricing.price-list.entry-updated.v1", map[string]any{"id": l.URN, "entryId": entryID,
			"patch": map[string]any{"priceModel": e.Model, "scope": e.Scope, "priority": e.Priority, "validTo": e.ValidTo}})
	})
	return out, err
}

// ---------------------------------------------------------------- snapshots and lifecycle

func (s *PRC) nextSnapshot(ctx context.Context, tx pgx.Tx) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx, `INSERT INTO ucos_pricing.snapshot_versions (tenant_id, version) VALUES (current_setting('ucos.tenant_id')::uuid, 1)
		ON CONFLICT (tenant_id) DO UPDATE SET version = ucos_pricing.snapshot_versions.version + 1 RETURNING version`).Scan(&v)
	return v, err
}

func (s *PRC) currentSnapshot(ctx context.Context, tx pgx.Tx) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx, `SELECT coalesce((SELECT version FROM ucos_pricing.snapshot_versions
		WHERE tenant_id = current_setting('ucos.tenant_id')::uuid), 0)`).Scan(&v)
	return v, err
}

// endRows ends published rows by MVCC: the current row stops at snapshot v, and a successor row with validTo = end
// takes over from v (when the window stays non-empty). Old snapshots replay unchanged (CR-011-004-03).
func (s *PRC) endRows(ctx context.Context, tx pgx.Tx, l PriceList, rows []Entry, end time.Time, v int64) error {
	for _, e := range rows {
		if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_entries SET snapshot_to = $4
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND list_id = $1 AND entry_id = $2 AND row_seq = $3`,
			l.ID, e.EntryID, e.rowSeq, v); err != nil {
			return err
		}
		if e.ValidTo != nil && !end.Before(*e.ValidTo) {
			end = *e.ValidTo
		}
		if end.After(e.ValidFrom) {
			succ := e
			succ.ValidTo = &end
			if err := s.insertEntry(ctx, tx, PriceList{ID: l.ID, Scope: e.listScope}, succ, e.rowSeq+1, &v); err != nil {
				return err
			}
		}
	}
	return nil
}

// EndEntry implements EndPriceEntry (also on published lists: end-dating only).
func (s *PRC) EndEntry(ctx context.Context, p svc.Principal, ref, entryID string, validTo time.Time) (PriceList, error) {
	var out PriceList
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		l, err := s.loadList(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		draft := l.State == "draft" || l.State == "in-review" || l.State == "approved"
		cur, err := s.entries(ctx, tx, l.ID, draft)
		if err != nil {
			return err
		}
		var target []Entry
		for _, e := range cur {
			if e.EntryID == entryID {
				target = append(target, e)
			}
		}
		if len(target) == 0 {
			return svc.ErrNotFound
		}
		if draft {
			if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_entries SET valid_to = $3 WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
				AND list_id = $1 AND entry_id = $2 AND snapshot_from IS NULL`, l.ID, entryID, validTo.UTC()); err != nil {
				return err
			}
		} else {
			v, err := s.nextSnapshot(ctx, tx)
			if err != nil {
				return err
			}
			if err := s.endRows(ctx, tx, l, target, validTo.UTC(), v); err != nil {
				return err
			}
		}
		if err := s.bump(ctx, tx, l.ID); err != nil {
			return err
		}
		if out, err = s.loadList(ctx, tx, l.ID, false); err != nil {
			return err
		}
		return s.event(ctx, tx, p, out, "ucos.pricing.price-list.entry-ended.v1", map[string]any{"id": out.URN, "entryId": entryID,
			"subject": target[0].Subject, "validTo": validTo.UTC()})
	})
	return out, err
}

func (s *PRC) transition(ctx context.Context, p svc.Principal, ref string, fn func(tx pgx.Tx, l *PriceList) (string, map[string]any, error)) (PriceList, error) {
	var out PriceList
	err := s.DB.InTenantTx(ctx, p.TenantID, func(tx pgx.Tx) error {
		l, err := s.loadList(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		typ, payload, err := fn(tx, &l)
		if err != nil {
			return err
		}
		approvals, _ := json.Marshal(l.Approvals)
		plan, _ := json.Marshal(l.Plan)
		if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_lists SET state = $2, approvals = $3, plan = $4, effective_at = $5, revision = revision + 1
			WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, l.ID, l.State, approvals, plan, l.EffectiveAt); err != nil {
			return err
		}
		if out, err = s.loadList(ctx, tx, l.ID, false); err != nil {
			return err
		}
		payload["id"] = out.URN
		return s.event(ctx, tx, p, out, typ, payload)
	})
	return out, err
}

// changePercent is pricing.approval's measure maxEntryChangePercent: the largest relative change of a flat or
// per-unit amount against the latest published version of the same code (0 for a first version).
func (s *PRC) changePercent(ctx context.Context, tx pgx.Tx, l PriceList, drafts []Entry) (*big.Rat, error) {
	var prevID string
	err := tx.QueryRow(ctx, `SELECT id FROM ucos_pricing.price_lists WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
		AND code = $1 AND state IN ('published','scheduled') ORDER BY version DESC LIMIT 1`, l.Code).Scan(&prevID)
	if errors.Is(err, pgx.ErrNoRows) {
		return new(big.Rat), nil
	}
	if err != nil {
		return nil, err
	}
	prev, err := s.entries(ctx, tx, strings.TrimSpace(prevID), false)
	if err != nil {
		return nil, err
	}
	amount := func(m map[string]any) *big.Rat {
		if k := svc.Str(m, "kind"); k == "flat" || k == "per-unit" {
			if mm, err := moneyOf(m["amount"]); err == nil {
				if r, err := mm.Rat(); err == nil {
					return r
				}
			}
		}
		return nil
	}
	maxPct := new(big.Rat)
	for _, d := range drafts {
		for _, o := range prev {
			if o.Subject != d.Subject || o.ChargeType != d.ChargeType || scopeDigest(o.Scope) != scopeDigest(d.Scope) {
				continue
			}
			a, b := amount(o.Model), amount(d.Model)
			if a == nil || b == nil || a.Sign() == 0 {
				continue
			}
			pct := new(big.Rat).Mul(new(big.Rat).Abs(new(big.Rat).Quo(new(big.Rat).Sub(b, a), a)), big.NewRat(100, 1))
			if pct.Cmp(maxPct) > 0 {
				maxPct = pct
			}
		}
	}
	return maxPct, nil
}

// Submit implements SubmitPriceList: draft -> in-review, with the approval plan of pricing.approval.
func (s *PRC) Submit(ctx context.Context, p svc.Principal, ref string) (PriceList, error) {
	var policy struct {
		Tiers []struct {
			UpTo   any     `json:"upTo"`
			Stages []Stage `json:"stages"`
		} `json:"tiers"`
	}
	if err := s.Meta.Config(ctx, p.TenantSlug, s.Cfg.Approval, &policy); err != nil {
		return PriceList{}, err
	}
	return s.transition(ctx, p, ref, func(tx pgx.Tx, l *PriceList) (string, map[string]any, error) {
		if l.State != "draft" {
			return "", nil, svc.Errf(409, "E-PRC-INVALID-STATE", "only draft lists are submitted (state %s)", l.State)
		}
		drafts, err := s.entries(ctx, tx, l.ID, true)
		if err != nil {
			return "", nil, err
		}
		if len(drafts) == 0 {
			return "", nil, svc.Errf(422, "E-PRC-EMPTY-LIST", "a price list needs at least one entry")
		}
		pct, err := s.changePercent(ctx, tx, *l, drafts)
		if err != nil {
			return "", nil, err
		}
		for _, t := range policy.Tiers {
			up, ok := rat(fmt.Sprint(t.UpTo))
			if fmt.Sprint(t.UpTo) == "unbounded" || (ok && pct.Cmp(up) <= 0) {
				l.Plan = t.Stages
				break
			}
		}
		if len(l.Plan) == 0 {
			return "", nil, svc.Errf(422, "E-PRC-NO-APPROVAL-PLAN", "pricing.approval has no tier for a %s%% change", pct.FloatString(2))
		}
		l.State, l.Approvals = "in-review", []map[string]any{}
		return "ucos.pricing.price-list.submitted.v1", map[string]any{"maxEntryChangePercent": pct.FloatString(2)}, nil
	})
}

// Approve implements ApprovePriceList: the approver is never the author (CR-PRC-02), holds a role of the current
// stage, and approves once; when every stage reaches its quorum the list is approved. A rejection returns it to draft.
func (s *PRC) Approve(ctx context.Context, p svc.Principal, ref, decision, comment string) (PriceList, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, l *PriceList) (string, map[string]any, error) {
		if l.State != "in-review" {
			return "", nil, svc.Errf(409, "E-PRC-INVALID-STATE", "only lists in review are approved (state %s)", l.State)
		}
		if p.Party == l.Author {
			return "", nil, svc.Errf(403, "E-PRC-SOD-VIOLATION", "the author of a price list cannot approve it (CR-PRC-02)")
		}
		for _, a := range l.Approvals {
			if a["approver"] == p.Party {
				return "", nil, svc.Errf(409, "E-PRC-ALREADY-APPROVED", "each approver decides once")
			}
		}
		if decision == "reject" {
			l.State, l.Approvals = "draft", []map[string]any{}
			return "ucos.pricing.price-list.rejected.v1", map[string]any{"approver": p.Party, "comment": comment}, nil
		}
		if decision != "approve" {
			return "", nil, svc.Errf(422, "E-API-VALIDATION", "decision must be approve or reject")
		}
		stage := len(l.Plan)
		count := map[int]int{}
		for _, a := range l.Approvals {
			n, _ := a["stage"].(json.Number).Int64()
			count[int(n)]++
		}
		for i, st := range l.Plan {
			if count[i] < st.Quorum {
				stage = i
				break
			}
		}
		if stage >= len(l.Plan) {
			return "", nil, svc.Errf(409, "E-PRC-INVALID-STATE", "the approval plan is already complete")
		}
		eligible := false
		for _, r := range p.Roles {
			for _, want := range l.Plan[stage].ApproverRoles {
				eligible = eligible || r == want
			}
		}
		if !eligible {
			return "", nil, svc.Errf(403, "E-PRC-NOT-APPROVER", "stage %d requires one of %v", stage+1, l.Plan[stage].ApproverRoles)
		}
		l.Approvals = append(l.Approvals, map[string]any{"approver": p.Party, "stage": json.Number(fmt.Sprint(stage)),
			"at": s.Clock.Now().UTC(), "comment": comment})
		count[stage]++
		done := true
		for i, st := range l.Plan {
			done = done && count[i] >= st.Quorum
		}
		if done {
			l.State = "approved"
		}
		return "ucos.pricing.price-list.approved.v1", map[string]any{"approver": p.Party, "stage": stage + 1, "complete": done}, nil
	})
}

// Publish implements PublishPriceList: the draft rows become the published truth from a new snapshot version; the
// previous published version of the same code is superseded at effectiveAt (its rows end by MVCC); INV-PRC-2 holds
// across every other published list.
func (s *PRC) Publish(ctx context.Context, p svc.Principal, ref string, effectiveAt *time.Time) (PriceList, error) {
	return s.transition(ctx, p, ref, func(tx pgx.Tx, l *PriceList) (string, map[string]any, error) {
		if l.State != "approved" {
			return "", nil, svc.Errf(409, "E-PRC-INVALID-STATE", "only approved lists are published (state %s)", l.State)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('ucos_pricing.publish:' || current_setting('ucos.tenant_id')))`); err != nil {
			return "", nil, err
		}
		now := s.Clock.Now().UTC()
		eff := now
		if effectiveAt != nil && effectiveAt.After(now) {
			eff = effectiveAt.UTC()
		}
		drafts, err := s.entries(ctx, tx, l.ID, true)
		if err != nil {
			return "", nil, err
		}
		var prevID string
		_ = tx.QueryRow(ctx, `SELECT id FROM ucos_pricing.price_lists WHERE tenant_id = current_setting('ucos.tenant_id')::uuid
			AND code = $1 AND id <> $2 AND state IN ('published','scheduled') ORDER BY version DESC LIMIT 1`, l.Code, l.ID).Scan(&prevID)
		prevID = strings.TrimSpace(prevID)
		rows, err := tx.Query(ctx, `SELECT `+entryCols+` FROM ucos_pricing.price_entries e JOIN ucos_pricing.price_lists l
			ON l.tenant_id = e.tenant_id AND l.id = e.list_id
			WHERE e.tenant_id = current_setting('ucos.tenant_id')::uuid AND e.snapshot_from IS NOT NULL AND e.snapshot_to IS NULL
			  AND e.list_id <> $1 AND e.list_id <> $2`, l.ID, prevID)
		if err != nil {
			return "", nil, err
		}
		others, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Entry, error) { return scanEntry(r) })
		if err != nil {
			return "", nil, err
		}
		for _, d := range drafts {
			de := append(append([]ctxrt.Constraint{}, l.Scope...), d.Scope...)
			from := d.ValidFrom
			if from.Before(eff) {
				from = eff
			}
			for _, o := range others {
				oe := append(append([]ctxrt.Constraint{}, o.listScope...), o.Scope...)
				if o.Subject == d.Subject && o.ChargeType == d.ChargeType && o.Currency == d.Currency && scopeDigest(oe) == scopeDigest(de) &&
					overlaps(o.ValidFrom, o.ValidTo, from, d.ValidTo) {
					return "", nil, svc.Errf(409, "E-PRC-OVERLAP", "entry %s overlaps published entry %s of list %s (INV-PRC-2)", d.EntryID, o.EntryID, o.ListID)
				}
			}
		}
		v, err := s.nextSnapshot(ctx, tx)
		if err != nil {
			return "", nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_entries SET snapshot_from = $2,
			valid_from = greatest(valid_from, $3) WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND list_id = $1 AND snapshot_from IS NULL`,
			l.ID, v, eff); err != nil {
			return "", nil, err
		}
		if prevID != "" {
			prev, err := s.loadList(ctx, tx, prevID, true)
			if err != nil {
				return "", nil, err
			}
			prevRows, err := s.entries(ctx, tx, prev.ID, false)
			if err != nil {
				return "", nil, err
			}
			if err := s.endRows(ctx, tx, prev, prevRows, eff, v); err != nil {
				return "", nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE ucos_pricing.price_lists SET state = 'superseded', revision = revision + 1
				WHERE tenant_id = current_setting('ucos.tenant_id')::uuid AND id = $1`, prev.ID); err != nil {
				return "", nil, err
			}
		}
		l.EffectiveAt = &eff
		l.State = "published"
		if eff.After(now) {
			l.State = "scheduled"
		}
		subjects := map[string]bool{}
		for _, d := range drafts {
			subjects[d.Subject] = true
		}
		return "ucos.pricing.price-list.published.v1", map[string]any{"version": l.Version, "effectiveAt": eff, "snapshotVersion": v,
			"subjectsAffected": len(subjects)}, nil
	})
}

// BulkInput is the ApplyBulkPriceChange input.
type BulkInput struct {
	Selector        string     `json:"selector"` // CEL over entry {subject, chargeType, priceModel}
	Formula         string     `json:"formula"`  // CEL over {amountMinor: int} -> int (minor units)
	TargetValidFrom *time.Time `json:"targetValidFrom"`
}

// BulkChange implements ApplyBulkPriceChange: a new draft version of the source list's code whose selected flat and
// per-unit amounts are transformed by the formula (integer minor units; no floating point).
func (s *PRC) BulkChange(ctx context.Context, p svc.Principal, sourceRef string, in BulkInput) (PriceList, error) {
	src, err := s.GetList(ctx, p, sourceRef)
	if err != nil {
		return PriceList{}, err
	}
	if in.Formula == "" {
		return PriceList{}, svc.Errf(422, "E-API-VALIDATION", "formula is required")
	}
	srcRef := src.URN
	nl, err := s.CreateList(ctx, p, ListInput{Code: src.Code, Label: src.Label, Currency: src.Currency, MultiCurrency: src.MultiCurrency,
		Scope: src.Scope, Priority: src.Priority, ValidFrom: in.TargetValidFrom, ValidTo: src.ValidTo, BasedOn: &srcRef, Derivation: &in.Formula})
	if err != nil {
		return PriceList{}, err
	}
	entries, err := s.FindEntries(ctx, p, src.ID, "")
	if err != nil {
		return PriceList{}, err
	}
	var inputs []EntryInput
	for _, e := range entries {
		model := e.Model
		if in.Selector != "" {
			sel, err := s.Meta.Engine.EvalCEL(in.Selector, map[string]any{"entry": map[string]any{"subject": e.Subject,
				"chargeType": e.ChargeType, "priceModel": e.Model}})
			if err != nil {
				return PriceList{}, svc.Errf(422, "E-API-VALIDATION", "selector: %v", err)
			}
			if sel == true {
				if model, err = s.transform(model, in.Formula); err != nil {
					return PriceList{}, err
				}
			}
		} else if model, err = s.transform(model, in.Formula); err != nil {
			return PriceList{}, err
		}
		subject := e.Subject
		inputs = append(inputs, EntryInput{Subject: subject, ChargeType: e.ChargeType, Model: model, Scope: e.Scope, Priority: e.Priority,
			Currency: e.Currency, Recurrence: e.Recurrence, MeterRef: e.MeterRef})
	}
	if len(inputs) > 0 {
		if nl, _, err = s.AddEntries(ctx, p, nl.ID, nl.Revision, inputs); err != nil {
			return PriceList{}, err
		}
	}
	return nl, nil
}

func (s *PRC) transform(model map[string]any, formula string) (map[string]any, error) {
	if k := svc.Str(model, "kind"); k != "flat" && k != "per-unit" {
		return model, nil
	}
	m, err := moneyOf(model["amount"])
	if err != nil {
		return nil, err
	}
	n, _ := new(big.Int).SetString(m.AmountMinor, 10)
	out, err := s.Meta.Engine.EvalCEL(formula, map[string]any{"amountMinor": n.Int64()})
	if err != nil {
		return nil, svc.Errf(422, "E-API-VALIDATION", "formula: %v", err)
	}
	v, ok := toInt(out)
	if !ok {
		return nil, svc.Errf(422, "E-API-VALIDATION", "formula must return an integer amount in minor units")
	}
	copyM := map[string]any{}
	for k, x := range model {
		copyM[k] = x
	}
	copyM["amount"] = map[string]any{"amountMinor": v.String(), "currency": m.Currency, "scale": m.Scale}
	return copyM, nil
}

func toInt(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case int64:
		return big.NewInt(x), true
	case int:
		return big.NewInt(int64(x)), true
	case uint64:
		return new(big.Int).SetUint64(x), true
	case json.Number:
		n, ok := new(big.Int).SetString(x.String(), 10)
		return n, ok
	}
	return nil, false
}
