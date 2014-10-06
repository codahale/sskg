package sskg_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/codahale/sskg"
)

func TestNext(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	for i := 0; i < 10000; i++ {
		seq.Next()
	}

	if v := seq.Key(); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeek(t *testing.T) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(10000)

	if v := seq.Key(); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeekTooFar(t *testing.T) {
	defer func() {
		e := recover()
		if e != "keyspace exhausted" {
			t.Errorf("Unexpected error: %v", e)
		}
	}()

	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	seq.Seek(1 << 33)

	t.Fatal("expected to exhaust the keyspace")
}

func BenchmarkNext(b *testing.B) {
	seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq.Next()
	}
}

func BenchmarkNext1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
		for j := 0; j < 1000; j++ {
			seq.Next()
		}
	}
}

func BenchmarkSeek1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(sha256.New, make([]byte, 32), 1<<32)
		seq.Seek(1000)
	}
}

var (
	expected = []byte{
		0x46, 0x36, 0x7f, 0x8f, 0x2b, 0x62, 0xc8, 0x4d, 0x8d, 0x40, 0xb5, 0x36,
		0x7b, 0xac, 0x77, 0xc8, 0xae, 0xb2, 0xde, 0x72, 0x7e, 0x50, 0xb5, 0x1a,
		0x9e, 0xae, 0x22, 0xa3, 0xe0, 0x21, 0xb4, 0x6f,
	}
)
