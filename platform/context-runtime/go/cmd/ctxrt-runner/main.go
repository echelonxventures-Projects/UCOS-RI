// Command ctxrt-runner is the conformance runner of the Go ucos-context-runtime: JSON Lines in, JSON Lines out
// (contracts/context-runtime/semantics.md §1).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"ucos.dev/ri/contextruntime/ctxrt"
)

type line struct {
	Kind        string             `json:"kind"`
	ID          string             `json:"id"`
	World       json.RawMessage    `json:"world"`
	Dimensions  []ctxrt.Dimension  `json:"dimensions"`
	Op          string             `json:"op"`
	FactKind    string             `json:"factKind"`
	Candidates  []ctxrt.Candidate  `json:"candidates"`
	Context     ctxrt.Context      `json:"context"`
	Config      ctxrt.Config       `json:"config"`
	Explicit    map[string]any     `json:"explicit"`
	Principal   map[string]any     `json:"principal"`
	Derivations []ctxrt.Derivation `json:"derivations"`
	AsOf        string             `json:"asOf"`
	Granularity int64              `json:"cacheGranularitySeconds"`
	Case        json.RawMessage    `json:"case"`
	Iterations  int                `json:"iterations"`
}

func main() {
	worlds := map[string]*ctxrt.World{}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for in.Scan() {
		var l line
		dec := json.NewDecoder(bytes.NewReader(in.Bytes()))
		dec.UseNumber()
		if err := dec.Decode(&l); err != nil {
			fmt.Fprintln(os.Stderr, "bad input line:", err)
			os.Exit(2)
		}
		switch l.Kind {
		case "world":
			worlds[l.ID] = ctxrt.NewWorld(l.ID, l.Dimensions)
		case "case":
			res := run(worlds, l)
			emit(out, map[string]any{"id": l.ID, "result": res})
		case "bench":
			var c line
			dec := json.NewDecoder(bytes.NewReader(l.Case))
			dec.UseNumber()
			if err := dec.Decode(&c); err != nil {
				fmt.Fprintln(os.Stderr, "bad bench case:", err)
				os.Exit(2)
			}
			c.World = l.World
			durs := make([]time.Duration, 0, l.Iterations)
			for i := 0; i < l.Iterations; i++ {
				t := time.Now()
				run(worlds, c)
				durs = append(durs, time.Since(t))
			}
			sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
			pct := func(p int) int64 { return durs[(len(durs)-1)*p/100].Microseconds() }
			emit(out, map[string]any{"id": l.ID, "p50Micros": pct(50), "p99Micros": pct(99)})
		default:
			fmt.Fprintln(os.Stderr, "unknown kind:", l.Kind)
			os.Exit(2)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(worlds map[string]*ctxrt.World, l line) any {
	var wid string
	_ = json.Unmarshal(l.World, &wid)
	w := worlds[wid]
	if w == nil {
		fmt.Fprintln(os.Stderr, "unknown world:", wid)
		os.Exit(2)
	}
	switch l.Op {
	case "resolve":
		return ctxrt.Resolve(w, l.FactKind, l.Candidates, l.Context, l.Config)
	case "assemble":
		return ctxrt.Assemble(w, l.Explicit, l.Principal, l.Derivations, l.AsOf, l.Granularity)
	}
	fmt.Fprintln(os.Stderr, "unknown op:", l.Op)
	os.Exit(2)
	return nil
}

func emit(w *bufio.Writer, v any) {
	b, err := ctxrt.Canonical(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(2)
	}
	w.Write(b)
	w.WriteByte('\n')
}
