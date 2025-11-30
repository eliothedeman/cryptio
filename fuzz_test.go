package cryptio

import (
	"bytes"
	"crypto/aes"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

// FuzzReadWriteSmall tests ReadWriteSeeker with small data (< block size)
func FuzzReadWriteSmall(f *testing.F) {
	// Seed corpus with some initial test cases
	f.Add([]byte("hello"), []byte("1234567890123456")) // 16-byte key for AES-128
	f.Add([]byte("test"), []byte("12345678901234567890123456789012")) // 32-byte key for AES-256
	f.Add([]byte("a"), []byte("123456789012345678901234")) // 24-byte key for AES-192
	f.Add([]byte(""), []byte("1234567890123456"))

	f.Fuzz(func(t *testing.T, data []byte, key []byte) {
		// Ensure key is valid AES size (16, 24, or 32 bytes)
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			t.Skip("Invalid key size")
		}

		// Skip if data is too large for small test
		if len(data) >= 32 {
			t.Skip("Data too large for small test")
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Skip("Failed to create cipher")
		}

		// Create temp file for testing
		tmpFile, err := ioutil.TempFile("", "fuzz_test_*")
		if err != nil {
			t.Skip("Failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		// Create ReadWriteSeeker
		rws := ReadWriteSeeker(tmpFile, block)

		// Write data
		n, err := rws.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Fatalf("Write returned %d, expected %d", n, len(data))
		}

		// Seek back to beginning
		_, err = rws.Seek(0, 0)
		if err != nil {
			t.Fatalf("Seek failed: %v", err)
		}

		// Read data back
		got := make([]byte, len(data))
		if len(data) > 0 {
			n, err = io.ReadFull(rws, got)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				t.Fatalf("Read failed: %v", err)
			}
		}

		// Verify round-trip
		if !bytes.Equal(data, got) {
			t.Fatalf("Round-trip failed:\noriginal:  % x\ndecrypted: % x", data, got)
		}
	})
}

// FuzzReadWriteLarge tests ReadWriteSeeker with larger data
func FuzzReadWriteLarge(f *testing.F) {
	// Seed corpus
	f.Add([]byte("this is a longer test string with more data"), []byte("1234567890123456"))
	f.Add([]byte("testing with random bytes and longer content"), []byte("12345678901234567890123456789012"))
	f.Add(make([]byte, 100), []byte("1234567890123456"))

	f.Fuzz(func(t *testing.T, data []byte, key []byte) {
		// Ensure key is valid AES size
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			t.Skip("Invalid key size")
		}

		// Skip empty data
		if len(data) == 0 {
			t.Skip("Empty data")
		}

		// Limit data size to keep fuzzing fast (but still test larger sizes)
		if len(data) > 1024 {
			data = data[:1024]
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Skip("Failed to create cipher")
		}

		// Create temp file
		tmpFile, err := ioutil.TempFile("", "fuzz_test_*")
		if err != nil {
			t.Skip("Failed to create temp file")
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		// Create ReadWriteSeeker
		rws := ReadWriteSeeker(tmpFile, block)

		// Write data
		n, err := rws.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Fatalf("Write returned %d, expected %d", n, len(data))
		}

		// Seek back
		_, err = rws.Seek(0, 0)
		if err != nil {
			t.Fatalf("Seek failed: %v", err)
		}

		// Read back
		got, err := io.ReadAll(rws)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if !bytes.Equal(data, got) {
			t.Fatalf("Data mismatch (len=%d vs %d)", len(data), len(got))
		}
	})
}

