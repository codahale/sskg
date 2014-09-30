package sskg_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/codahale/sskg"
)

func TestNext(t *testing.T) {
	seq := sskg.New(make([]byte, 64), 1<<32, sskg.HMAC(sha256.New))
	for i := 0; i < 10000; i++ {
		seq.Next()
	}

	if v := seq.Key(); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeek(t *testing.T) {
	seq := sskg.New(make([]byte, 64), 1<<32, sskg.HMAC(sha256.New))
	seq.Seek(10000)

	if v := seq.Key(); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func BenchmarkNext(b *testing.B) {
	seq := sskg.New(make([]byte, 64), 1<<32, sskg.HMAC(sha256.New))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq.Next()
	}
}

var (
	expected = []byte{
		0x43, 0x7a, 0x2f, 0x15, 0x9b, 0xeb, 0xdf, 0x35, 0x34, 0x8a, 0xb2, 0x79,
		0x6d, 0x31, 0x3f, 0x45, 0xa2, 0x03, 0xcc, 0xde, 0xe7, 0xeb, 0xe9, 0x55,
		0x57, 0x3e, 0x14, 0xbe, 0x18, 0xd8, 0x29, 0x1e,
	}
)
