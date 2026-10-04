package infrastructure

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"regexp"
	"sync"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULIDs generates ULIDs (48-bit millisecond time + 80 random bits, Crockford base32).
type ULIDs struct{ mu sync.Mutex }

// New returns a new ULID string.
func (u *ULIDs) New() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	u.mu.Lock()
	_, err := rand.Read(b[6:])
	u.mu.Unlock()
	if err != nil {
		panic(err)
	}
	// 128 bits → 26 base32 chars, most significant first (first char carries 3 bits).
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}

// UTCClock is the production clock, truncated to microseconds (PostgreSQL timestamptz precision) so that
// stored and published instants are identical.
type UTCClock struct{}

// Now returns the current UTC instant at microsecond precision.
func (UTCClock) Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// tenantNamespace is the UUIDv5 namespace for tenant ids derived from slugs.
var tenantNamespace = [16]byte{0x6b, 0x2f, 0x1c, 0x52, 0x0e, 0x5a, 0x4d, 0x61, 0x9a, 0x43, 0x75, 0x63, 0x6f, 0x73, 0x74, 0x6e}

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// StaticTenants is the ucos-lite tenant directory: tenant id = UUIDv5(tenantNamespace, slug) (RFC 9562).
// Later slices replace it with the DOM-RTM tenant directory behind the same port.
type StaticTenants struct{}

// Resolve maps a tenant slug to its tenant id.
func (StaticTenants) Resolve(slug string) (string, error) {
	if !slugPattern.MatchString(slug) {
		return "", fmt.Errorf("invalid tenant slug %q", slug)
	}
	h := sha1.New()
	h.Write(tenantNamespace[:])
	h.Write([]byte(slug))
	s := h.Sum(nil)[:16]
	s[6] = s[6]&0x0f | 0x50
	s[8] = s[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16]), nil
}
