package ofr

import (
	"fmt"
	"math/rand"
	"testing"
)

func explicitAllowed(s Slot, ref string) bool {
	for _, o := range s.Allowed.Objects {
		if o == ref {
			return true
		}
	}
	return false
}

func randomOffer(r *rand.Rand) []Slot {
	n := 1 + r.Intn(8)
	slots := make([]Slot, n)
	for i := range slots {
		mx := 1 + r.Intn(3)
		mn := 0
		if r.Intn(4) == 0 {
			mn = 1 + r.Intn(mx)
		}
		s := Slot{SlotCode: fmt.Sprintf("s%d", i), MinQty: mn, MaxQty: mx, Allowed: Allowed{Objects: []string{fmt.Sprintf("o%d", i)}}}
		if r.Intn(3) == 0 {
			s.DefaultSelections = []Selection{{ObjectRef: s.Allowed.Objects[0], Qty: max(mn, 1)}}
		}
		slots[i] = s
	}
	for i := range slots {
		for j := range slots {
			if i == j {
				continue
			}
			switch r.Intn(12) {
			case 0:
				slots[i].RequiresSlots = append(slots[i].RequiresSlots, slots[j].SlotCode)
			case 1:
				slots[i].ExcludesSlots = append(slots[i].ExcludesSlots, slots[j].SlotCode)
			}
		}
	}
	return slots
}

// bruteForce enumerates every slot-usage assignment: which are consistent with the partial selections, and for each
// slot whether some consistent assignment uses / omits it.
func bruteForce(slots []Slot, used map[string]bool) (bool, map[string][2]bool) {
	idx := map[string]int{}
	for i, s := range slots {
		idx[s.SlotCode] = i
	}
	any := false
	per := map[string][2]bool{}
	for mask := 0; mask < 1<<len(slots); mask++ {
		on := func(code string) bool { return mask&(1<<idx[code]) != 0 }
		ok := true
		for _, s := range slots {
			u := on(s.SlotCode)
			if (used[s.SlotCode] || s.MinQty > 0) && !u {
				ok = false
			}
			if !u {
				continue
			}
			for _, r := range s.RequiresSlots {
				ok = ok && on(r)
			}
			for _, x := range s.ExcludesSlots {
				ok = ok && !on(x)
			}
		}
		if !ok {
			continue
		}
		any = true
		for _, s := range slots {
			f := per[s.SlotCode]
			if on(s.SlotCode) {
				f[0] = true
			} else {
				f[1] = true
			}
			per[s.SlotCode] = f
		}
	}
	return any, per
}

// TestConfiguratorMatchesBruteForce is CR-OFR-01: on 10^4 random offers of at most 8 slots the Configurator's
// consistency, per-slot options and validity equal brute-force enumeration, and every configuration it calls valid
// passes the exact Check.
func TestConfiguratorMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for n := 0; n < 10000; n++ {
		slots := randomOffer(r)
		if ValidateSlots(slots) != nil {
			t.Fatalf("generator produced an invalid offer")
		}
		var partial []Selection
		used := map[string]bool{}
		qtyOK := true
		for _, s := range slots {
			if r.Intn(3) == 0 {
				q := 1 + r.Intn(s.MaxQty+1) // sometimes above max
				partial = append(partial, Selection{SlotCode: s.SlotCode, ObjectRef: s.Allowed.Objects[0], Qty: q})
				used[s.SlotCode] = true
				qtyOK = qtyOK && q <= s.MaxQty && q >= s.MinQty
			}
		}
		res := Configure(slots, partial, explicitAllowed)
		sat, per := bruteForce(slots, used)
		if res.Consistent != sat {
			t.Fatalf("case %d: consistent=%v, brute force %v (%+v, partial %+v)", n, res.Consistent, sat, slots, partial)
		}
		for _, s := range slots {
			o := res.Options[s.SlotCode]
			if o.Selectable != per[s.SlotCode][0] || o.Omittable != per[s.SlotCode][1] {
				t.Fatalf("case %d: options of %s = %+v, brute force %v", n, s.SlotCode, o, per[s.SlotCode])
			}
		}
		if want := sat && qtyOK; res.Valid != want {
			t.Fatalf("case %d: valid=%v, want %v (violations %+v)", n, res.Valid, want, res.Violations)
		}
		if res.Valid {
			if v := Check(slots, res.Configuration, explicitAllowed); len(v) > 0 {
				t.Fatalf("case %d: valid configuration fails Check: %+v", n, v)
			}
		}
	}
}

// TestCheckMatchesBruteForce: Check accepts a complete configuration exactly when every constraint holds.
func TestCheckMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for n := 0; n < 10000; n++ {
		slots := randomOffer(r)
		var config []Selection
		qty := map[string]int{}
		valid := true
		for _, s := range slots {
			if r.Intn(2) == 0 {
				continue
			}
			obj := s.Allowed.Objects[0]
			if r.Intn(10) == 0 {
				obj, valid = "stranger", false
			}
			q := 1 + r.Intn(s.MaxQty+1)
			config = append(config, Selection{SlotCode: s.SlotCode, ObjectRef: obj, Qty: q})
			if obj != "stranger" {
				qty[s.SlotCode] += q
			}
		}
		for _, s := range slots {
			q := qty[s.SlotCode]
			valid = valid && q <= s.MaxQty && q >= s.MinQty
			if q == 0 {
				continue
			}
			for _, x := range s.RequiresSlots {
				valid = valid && qty[x] > 0
			}
			for _, x := range s.ExcludesSlots {
				valid = valid && qty[x] == 0
			}
		}
		if got := len(Check(slots, config, explicitAllowed)) == 0; got != valid {
			t.Fatalf("case %d: Check valid=%v, brute force %v (%+v / %+v)", n, got, valid, slots, config)
		}
	}
}

func TestValidateSlots(t *testing.T) {
	bad := [][]Slot{
		{{SlotCode: "a", MaxQty: 0, Allowed: Allowed{Objects: []string{"x"}}}},
		{{SlotCode: "a", MaxQty: 1}},
		{{SlotCode: "a", MaxQty: 1, Allowed: Allowed{Objects: []string{"x"}, Types: []string{"T"}}}},
		{{SlotCode: "a", MaxQty: 1, Allowed: Allowed{Objects: []string{"x"}}, RequiresSlots: []string{"zz"}}},
		{{SlotCode: "a", MaxQty: 1, Allowed: Allowed{Objects: []string{"x"}}}, {SlotCode: "a", MaxQty: 1, Allowed: Allowed{Objects: []string{"x"}}}},
		{{SlotCode: "a", MinQty: 2, MaxQty: 3, Allowed: Allowed{Objects: []string{"x"}}, DefaultSelections: []Selection{{ObjectRef: "x", Qty: 1}}}},
	}
	for i, s := range bad {
		if ValidateSlots(s) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
