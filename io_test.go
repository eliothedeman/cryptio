package cryptio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/eliothedeman/randutil"
)

func randBlock(t testing.TB, size int) cipher.Block {
	t.Helper()
	b, err := aes.NewCipher(randutil.Bytes(size))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func tmpFile(t testing.TB) *os.File {
	t.Helper()
	f, err := ioutil.TempFile(os.TempDir(), strings.Replace(t.Name(), "/", "_", -1))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestReadSmall(t *testing.T) {
	b := randBlock(t, 32)
	f := tmpFile(t)
	r := ReadWriteSeeker(f, b)
	want := randutil.Bytes(10)

	_, err := r.Write(want)

	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	r.Seek(0, 0)

	_, err = r.Read(got)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(want, got) {
		t.Fail()
		cmpBytes(want, got)
	}

}
func TestReadLarge(t *testing.T) {
	b := randBlock(t, 32)
	f := tmpFile(t)
	r := ReadWriteSeeker(f, b)

	want := randutil.Bytes(24)
	_, err := r.Write(want)

	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	r.Seek(0, 0)

	_, err = r.Read(got)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(want, got) {
		t.Fatalf("\n% x\n% x", want, got)
	}
}

func TestWriteSmall(t *testing.T) {
	b := randBlock(t, 32)
	f := tmpFile(t)
	r := ReadWriteSeeker(f, b)

	buff := randutil.Bytes(1024)
	for i := 0; i < 1000; i++ {
		ws := randutil.IntRange(0, 1024)
		x, err := r.Write(buff[:ws])
		if err != nil {
			t.Fatal(err)
		}
		if x != ws {
			t.Errorf("Attempted to write %d wrote %d.", ws, x)
		}
	}
}

func BenchmarkWrite(b *testing.B) {
	x := randBlock(b, 32)
	f := tmpFile(b)
	r := ReadWriteSeeker(f, x)
	buff := randutil.Bytes(1024)
	b.Run("1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r.Write(buff)
		}
	})
	x = randBlock(b, 32)
	f = tmpFile(b)
	r = ReadWriteSeeker(f, x)
	buff = randutil.Bytes(32)
	b.Run("32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r.Write(buff)
		}
	})
}

func TestOffset(t *testing.T) {
	b := randBlock(t, 32)
	x := make([]byte, 44)
	x[22] = 6
	b.Encrypt(x, x)
	y := x[22]
	b.Decrypt(x, x)
	x[1] = 44
	b.Encrypt(x, x)
	z := x[22]
	if y != z {
		t.Fatalf("%x", x)
	}
}
