package registry

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID.
func NewULID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}

var tenantNamespace = [16]byte{0x6b, 0x2f, 0x1c, 0x52, 0x0e, 0x5a, 0x4d, 0x61, 0x9a, 0x43, 0x75, 0x63, 0x6f, 0x73, 0x74, 0x6e}

// tenantID is UUIDv5(namespace, slug) per contracts/kernel/tenancy.yaml.
func tenantID(slug string) string {
	h := sha1.Sum(append(tenantNamespace[:], []byte(slug)...))
	s := h[:16]
	s[6] = s[6]&0x0f | 0x50
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}
