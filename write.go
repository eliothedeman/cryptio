package cryptio

import (
	"crypto/cipher"
	"io"
)

type Writer struct {
	source io.Writer
	block  cipher.Block
	*buffer
}

func (w *Writer) Write(buff []byte) (int, error) {

	// prepare the beginning of the block
	block := w.block
	blockSize := block.BlockSize()
	blockOffset := w.offset % int64(blockSize)
	if blockOffset != 0 {
		tmp := make([]byte, blockSize)
		copy(tmp[blockOffset:], buff)
		block.Encrypt(tmp, tmp)
		copy(buff, tmp[blockOffset:])
	}

	// encrypt the rest
	stillToEncrypt := buff[blockOffset:]
	block.Encrypt(stillToEncrypt, stillToEncrypt)
	return w.source.Write(buff)
}
