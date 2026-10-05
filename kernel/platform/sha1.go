package platform

import "crypto/sha1"

// sha1Sum is SHA-1 as required by UUIDv5 (RFC 9562 §5.5); not used for integrity.
func sha1Sum(b []byte) []byte {
	s := sha1.Sum(b)
	return s[:]
}
