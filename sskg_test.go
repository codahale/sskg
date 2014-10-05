package sskg_test

import (
	"bytes"
	"testing"

	"github.com/codahale/sskg"
)

func TestNext(t *testing.T) {
	seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
	for i := 0; i < 10000; i++ {
		seq.Next()
	}

	if v := seq.Key(); !bytes.Equal(expected, v) {
		t.Errorf("Key was %#v, but expected %#v", v, expected)
	}
}

func TestSeek(t *testing.T) {
	seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
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

	seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
	seq.Seek(1 << 33)

	t.Fatal("expected to exhaust the keyspace")
}

func BenchmarkNext(b *testing.B) {
	seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq.Next()
	}
}

func BenchmarkNext1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
		for j := 0; j < 1000; j++ {
			seq.Next()
		}
	}
}

func BenchmarkSeek1000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		seq := sskg.New(make([]byte, 32), make([]byte, 32), 1<<32, 32)
		seq.Seek(1000)
	}
}

var (
	expected = []byte{
		0xf7, 0xd2, 0xf8, 0x38, 0xb0, 0x6b, 0x60, 0xe4, 0x29, 0xe1, 0x45, 0xe9,
		0xbb, 0xa4, 0x87, 0x76, 0xb8, 0xd6, 0x2a, 0xa4, 0xf1, 0x6c, 0x64, 0x2f,
		0x18, 0x13, 0x5e, 0x41, 0x0b, 0xc8, 0x7b, 0xce,
	}
)
