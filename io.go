package cryptio

import (
	"crypto/cipher"
	"errors"
	"io"
)

var internalBufferSize = 1024

// buffer for encrypting and decrypting data
type buffer struct {
	offset   int64
	source   io.ReadWriteSeeker
	block    cipher.Block
	internal []byte
}

// WrapReadWriteSeeker wraps an encrypted io.ReadWriteSeeker
func WrapReadWriteSeeker(rws io.ReadWriteSeeker, block cipher.Block) io.ReadWriteSeeker {
	return &buffer{
		offset:   0,
		source:   rws,
		block:    block,
		internal: make([]byte, block.BlockSize()),
	}
}

func (b *buffer) currentBlockOffset() int64 {
	return b.offset % int64(b.block.BlockSize())
}

func (b *buffer) Read(to []byte) (int, error) {
	var x, n int
	var err error
	total := len(to)
	for n < total {
		x, err = b.source.Read(b.internal[b.currentBlockOffset():])
		if err != nil {
			break
		}

		b.offset += int64(x)
		n += x
		b.block.Decrypt(b.internal, b.internal)
		size := copy(to, b.internal[b.currentBlockOffset():])
		to = to[size:]
	}

	return n, err
}

func (b *buffer) Write(buff []byte) (int, error) {
	// encrypt the whole buffer
	b.currentBlockOffset()

	var n int
	var written int
	var err error
	tmp := b.internal
	for n < len(buff) {
		offset := b.currentBlockOffset()
		coppied := int64(copy(tmp[offset:], buff[n:]))

		b.block.Encrypt(tmp, tmp)
		written, err = b.source.Write(tmp[offset : offset+coppied])
		if err != nil {
			return n, err
		}
		b.offset += int64(written)
		n += written

	}

	return n, nil
}

var (
	errNotAbsoluteSeek = errors.New("cryptio only supports absolute seeks")
)

func (b *buffer) Seek(offset int64, whence int) (int64, error) {
	if whence != 0 {
		return 0, errNotAbsoluteSeek
	}

	// save the previous offset incase there is an error
	po := b.offset
	i, err := b.source.Seek(offset, whence)

	if err != nil {
		b.offset = po
	}
	return i, err
}
