package ctxrt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Canonical encodes v as RFC 8785 (JCS) JSON restricted to integers (contracts/context-runtime/semantics.md §1 [C1][C2]).
// Supported: nil, bool, string, json.Number (integer), int, int64, []any, []string, map[string]any, Marshaler.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Marshaler lets result types encode themselves canonically.
type Marshaler interface{ Canonical() any }

func encode(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return fmt.Errorf("non-integer number %q", x)
		}
		b.WriteString(strconv.FormatInt(n, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case []string:
		b.WriteByte('[')
		for i, s := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, s)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := encode(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case Marshaler:
		return encode(b, x.Canonical())
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexdigits = "0123456789abcdef"

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexdigits[r>>4])
				b.WriteByte(hexdigits[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
