package cryptio

import (
	"io"
)

type reader struct {
	source io.Reader
	buffer
}

func (r *reader) Read(to []byte) (int, error) {
	var x, n int
	var err error
	total := len(to)
	var tmp = r.buffer.internal
	for n < total {
		x, err = r.source.Read(tmp[r.currentBlockOffset():])
		if err != nil {
			break
		}

		r.offset += int64(x)
		n += x
		r.block.Decrypt(tmp, tmp)
		size := copy(to, tmp[r.currentBlockOffset():])
		to = to[size:]
	}

	return n, err
}
