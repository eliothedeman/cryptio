package cryptio

import (
	"crypto/cipher"
	"io"
)

type writer struct {
	source io.Writer
	block  cipher.Block
	*buffer
}

func (w *writer) Write(buff []byte) (int, error) {
	block := w.block
	offset := int(w.offset % int64(block.BlockSize()))
	encrypt(offset, buff, w.block)
	n, err := w.source.Write(buff)
	w.offset += int64(n)
	decrypt(offset, buff, w.block)
	return n, err
}
