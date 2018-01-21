package cryptio

import (
	"errors"
)

var internalBufferSize = 1024

// buffer for encrypting and decrypting data
type buffer struct {
	offset   int64
	internal []byte
}

var (
	errNotAbsoluteSeek = errors.New("cryptio only supports absolute seeks")
)
