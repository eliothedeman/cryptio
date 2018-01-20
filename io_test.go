package cryptio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
	"os"
	"testing"

	"github.com/eliothedeman/randutil"
)

func randBlock(t *testing.T, size int) cipher.Block {
	t.Helper()
	b, err := aes.NewCipher(randutil.Bytes(size))
	if err != nil {
		t.Fatal(t)
	}

	return b
}

func tmpFile(t *testing.T) *os.File {
	t.Helper()
	f, err := ioutil.TempFile(os.TempDir(), t.Name())
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestReadSmall(t *testing.T) {
	b := randBlock(t, 32)
	f := tmpFile(t)
	r := WrapReadWriteSeeker(f, b)

	want := randutil.Bytes(10000)
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
		t.Fatalf("Wanted %x got %x", want, got)

	}

}

func TestWriteSmall(t *testing.T) {
	b := randBlock(t, 32)
	f := tmpFile(t)
	r := WrapReadWriteSeeker(f, b)

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
