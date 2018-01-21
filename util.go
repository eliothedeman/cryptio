package cryptio

import "crypto/cipher"

type transform func(a, b []byte)

func apply(offset, blockSize int, buff []byte, t transform) {
	isSmall := len(buff) < blockSize

	if offset != 0 || isSmall {
		tmp := make([]byte, blockSize)
		copy(tmp[offset:], buff)
		t(tmp, tmp)
		copy(buff, tmp[offset:])
		if isSmall {
			return
		}
	}

	t(buff, buff)
}

func decrypt(offset int, buff []byte, b cipher.Block) {
	apply(offset, b.BlockSize(), buff, b.Decrypt)
}
func encrypt(offset int, buff []byte, b cipher.Block) {
	apply(offset, b.BlockSize(), buff, b.Encrypt)
}
