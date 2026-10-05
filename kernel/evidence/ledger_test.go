package evidence

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// verify is an independent RFC 6962 §2.1.1 inclusion verifier.
func verify(leaf []byte, index, size int, path [][]byte, root []byte) bool {
	fn, sn, r := index, size-1, leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

func TestInclusionProofsForEveryTreeSize(t *testing.T) {
	var leaves [][]byte
	for n := 1; n <= 40; n++ {
		leaves = append(leaves, LeafHash([]byte(fmt.Sprint(n))))
		root := MTH(leaves)
		for m := 0; m < n; m++ {
			if !verify(leaves[m], m, n, Path(m, leaves), root) {
				t.Fatalf("proof for leaf %d of %d does not verify", m, n)
			}
		}
	}
	empty := sha256.Sum256(nil)
	if !bytes.Equal(MTH(nil), empty[:]) {
		t.Fatal("MTH of the empty tree is SHA-256 of the empty string")
	}
}
