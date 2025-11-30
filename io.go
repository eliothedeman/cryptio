package cryptio

import (
	"crypto/cipher"
	"errors"
	"io"
)

// buffer for encrypting and decrypting data
type buffer struct {
	offset   int64
	internal []byte
}

func newBuffer(size int) *buffer {
	return &buffer{
		offset:   0,
		internal: make([]byte, size),
	}
}

var (
	errNotAbsoluteSeek = errors.New("cryptio only supports absolute seeks")
)

type seeker struct {
	source io.Seeker
	*buffer
}

func (s *seeker) Seek(offset int64, whence int) (int64, error) {

	if whence != 0 {
		return 0, errNotAbsoluteSeek
	}

	n, err := s.source.Seek(offset, whence)
	if err == nil {
		s.offset = offset
	}

	return n, nil
}

// Reader creates a decrypting io.Reader
func Reader(r io.Reader, blk cipher.Block) io.Reader {
	return &reader{
		source: r,
		block:  blk,
		buffer: newBuffer(blk.BlockSize()),
	}
}

// Writer creates an encrypting io.Writer
func Writer(w io.Writer, blk cipher.Block) io.Writer {
	return &writer{
		source: w,
		block:  blk,
		buffer: newBuffer(blk.BlockSize()),
	}
}

// Seeker creates cryptio safe seeker
func Seeker(s io.Seeker, blk cipher.Block) io.Seeker {
	return &seeker{
		source: s,
		buffer: newBuffer(blk.BlockSize()),
	}
}

type readWriter struct {
	reader
	writer
}

// ReadWriter creates an encrypting/decrypting ReadWriter
func ReadWriter(rw io.ReadWriter, blk cipher.Block) io.ReadWriter {
	buff := newBuffer(blk.BlockSize())
	return &readWriter{
		reader: reader{
			source: rw,
			block:  blk,
			buffer: buff,
		},
		writer: writer{
			source: rw,
			block:  blk,
			buffer: buff,
		},
	}
}

type readWriteSeeker struct {
	reader
	writer
	seeker
}

// ReadWriteSeeker creates an encrypting/decrypting ReadWriteSeeker
func ReadWriteSeeker(rw io.ReadWriteSeeker, blk cipher.Block) io.ReadWriteSeeker {
	buff := newBuffer(blk.BlockSize())
	return &readWriteSeeker{
		reader: reader{
			source: rw,
			block:  blk,
			buffer: buff,
		},
		writer: writer{
			source: rw,
			block:  blk,
			buffer: buff,
		},
		seeker: seeker{
			source: rw,
			buffer: buff,
		},
	}
}
