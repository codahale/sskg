// Package sskg provides a Go implementation of Seekable Sequential Key
// Generators (SSKGs).
//
// An SSKG generates a sequence of forward-secure keys (e.g., for use as
// time-bounded authentication keys), while also providing a fast-forward
// functionality. This package provides an HMAC-based implementation of a binary
// tree-based SSKG as described by Marson and Poettering:
// https://eprint.iacr.org/2014/479.pdf.
//
// The canonical example of SSKG usage is cryptographically protected local
// logs. In this scenario, we have logs on a computer which are secured via
// MACs. If the MAC key is constant, an attacker can extract the key and forge
// or modify log entries in the past. The traditional solution to this is to use
// a foward-secure solution like a hash chain (e.g., K1 = H(K0); K2 =
// H(K1)). This ensures that an attacker who compromises the state of the logger
// cannot establish the state of the logger at an arbitrary point in time in the
// past (and therefore cannot forge log entries in the past).
//
// The use of hash chains presents a large computational expense to the
// auditors, however. In order to verify the MAC using the Nth key, the auditor
// must calculate (N-1) hashes, which may be cumbersome. An SSKG, in contrast,
// allows quickly seeking forward to arbitrary points of time (specifically,
// Marson and Poettering's tree-based SSKG can perform O(log N) seeks).
package sskg

import "math"

// A Seq is a sequence of forward-secure keys.
type Seq struct {
	nodes []node
	key   []byte
	size  int
}

// New creates a new Seq with the given key, seed, maximum number of keys, and
// key size.
func New(key, seed []byte, maxKeys, keySize uint) Seq {
	return Seq{
		nodes: []node{
			node{
				s: prf12(int(keySize), []byte("seed"), key, seed),
				h: uint(math.Ceil(math.Log2(float64(maxKeys) + 1))),
			},
		},
		key:  key,
		size: int(keySize),
	}
}

// Key returns the Seq's current key.
func (t Seq) Key() []byte {
	return prf12(t.size, []byte("key"), t.key, t.nodes[len(t.nodes)-1].s)
}

// Next advances the Seq's current key to the next in the sequence.
//
// (In the literature, this function is called Evolve.)
func (t *Seq) Next() {
	s, h := t.pop()

	if h > 1 {
		t.push(prf12(t.size, right, t.key, s), h-1)
		t.push(prf12(t.size, left, t.key, s), h-1)
	}
}

// Seek moves the Seq to the k-th key without having to calculate all of the
// intermediary keys. It is equivalent to, but faster than, k invocations of
// Next().
func (t *Seq) Seek(k int) {
	s, h := t.pop()

	for k > 0 {
		h--

		if h <= 0 {
			panic("keyspace exhausted")
		}

		pow := 1 << h
		if k < pow {
			t.push(prf12(t.size, right, t.key, s), h)
			s = prf12(t.size, left, t.key, s)
			k--
		} else {
			s = prf12(t.size, right, t.key, s)
			k -= pow
		}
	}

	t.push(s, h)
}

func (t *Seq) pop() ([]byte, uint) {
	node := t.nodes[len(t.nodes)-1]
	t.nodes = t.nodes[:len(t.nodes)-1]
	return node.s, node.h
}

func (t *Seq) push(s []byte, h uint) {
	t.nodes = append(t.nodes, node{s: s, h: h})
}

type node struct {
	s []byte
	h uint
}

var (
	right = []byte("right")
	left  = []byte("left")
)
