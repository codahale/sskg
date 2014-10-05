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
		0x7e, 0x08, 0x05, 0x55, 0x9a, 0x93, 0xc8, 0x9f, 0x17, 0x8f, 0x7f, 0x0a,
		0x8a, 0x05, 0xa7, 0x52, 0x10, 0xd2, 0x7d, 0x54, 0xb4, 0x8d, 0x42, 0xda,
		0x27, 0x44, 0x2d, 0x83, 0xaf, 0x3f, 0xf4, 0xfc,
	}
)
