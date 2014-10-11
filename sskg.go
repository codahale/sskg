// Package sskg provides a Go implementation of Seekable Sequential Key
// Generators (SSKGs). Specifically, this package provides an HKDF-based
// implementation of a binary tree-based SSKG as described by Marson and
// Poettering (https://eprint.iacr.org/2014/479.pdf) which features fast key
// advancing (~6μs) and low memory usage (O(log N)).
//
// An example of SSKG usage is cryptographically protected local logs. In this
// scenario, logs on a computer are secured via MACs. If the MAC key is
// constant, an attacker can extract the key and forge or modify log entries in
// the past.
//
// The traditional solution to this is to use a foward-secure solution like a
// hash chain, but this presents a large computational expense to auditors: in
// order to verify the MAC using the Nth key, the auditor must calculate N-1
// hashes, which may be cumbersome. An SSKG, in contrast, allows quickly seeking
// forward to arbitrary points of time (specifically, Marson and Poettering's
// tree-based SSKG can perform O(log N) seeks).
package sskg

import (
	"hash"
	"math"

	"code.google.com/p/go.crypto/hkdf"
)

// A Seq is a sequence of forward-secure keys.
type Seq struct {
	nodes []node
	alg   func() hash.Hash
	size  int
}

// New creates a new Seq with the given hash algorithm, seed, and maximum number
// of keys.
func New(alg func() hash.Hash, seed []byte, maxKeys uint) Seq {
	size := alg().Size()
	return Seq{
		nodes: []node{{
			k: prf(alg, size, []byte("seed"), seed),
			h: uint(math.Ceil(math.Log2(float64(maxKeys) + 1))),
		}},
		alg:  alg,
		size: size,
	}
}

// Key returns the Seq's current key of the given size.
func (s Seq) Key(size int) []byte {
	return prf(s.alg, size, []byte("key"), s.nodes[len(s.nodes)-1].k)
}

// Next advances the Seq's current key to the next in the sequence.
//
// (In the literature, this function is called Evolve.)
func (s *Seq) Next() {
	k, h := s.pop()

	if h > 1 {
		s.push(prf(s.alg, s.size, right, k), h-1)
		s.push(prf(s.alg, s.size, left, k), h-1)
	}
}

// Seek moves the Seq to the N-th key without having to calculate all of the
// intermediary keys. It is equivalent to, but faster than, N invocations of
// Next().
func (s *Seq) Seek(n int) {
	k, h := s.pop()

	for n > 0 {
		h--

		if h <= 0 {
			panic("keyspace exhausted")
		}

		pow := 1 << h
		if n < pow {
			s.push(prf(s.alg, s.size, right, k), h)
			k = prf(s.alg, s.size, left, k)
			n--
		} else {
			k = prf(s.alg, s.size, right, k)
			n -= pow
		}
	}

	s.push(k, h)
}

func (s *Seq) pop() ([]byte, uint) {
	node := s.nodes[len(s.nodes)-1]
	s.nodes = s.nodes[:len(s.nodes)-1]
	return node.k, node.h
}

func (s *Seq) push(k []byte, h uint) {
	s.nodes = append(s.nodes, node{k: k, h: h})
}

type node struct {
	k []byte
	h uint
}

var (
	right = []byte("right")
	left  = []byte("left")
)

func prf(alg func() hash.Hash, size int, label, seed []byte) []byte {
	buf := make([]byte, size)
	kdf := hkdf.New(alg, seed, nil, label)
	_, _ = kdf.Read(buf)
	return buf
}
