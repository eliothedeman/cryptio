package cryptio

import (
	"crypto/cipher"
	"fmt"
	"io"
)

type reader struct {
	source io.Reader
	block  cipher.Block
	*buffer
}

func (r *reader) Read(buff []byte) (int, error) {
	// read into the buffer
	n, err := r.source.Read(buff)

	block := r.block
	offset := int(r.offset % int64(block.BlockSize()))
	decrypt(offset, buff, block)
	r.offset += int64(n)
	return n, err
}

func cmpBytes(a, b []byte) {
	fmt.Printf("\n% x\n% x\n", a, b)
}
