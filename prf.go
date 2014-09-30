package sskg

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// A PRF is a pseudo-random function family.
type PRF func(i int, s []byte) []byte

// HMAC returns an HMAC-based PRF.
func HMAC(alg func() hash.Hash) PRF {
	return func(i int, s []byte) []byte {
		k := make([]byte, 8)
		binary.LittleEndian.PutUint64(k, uint64(i))

		h := hmac.New(alg, k)
		_, _ = h.Write(s)
		return h.Sum(nil)
	}
}
