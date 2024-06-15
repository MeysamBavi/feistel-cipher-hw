package fch

import (
	"crypto/cipher"
	"strconv"
)

const (
	KeySize   = 8
	BlockSize = 16
)

type KeySizeError int

func (k KeySizeError) Error() string {
	return "fch: invalid key size " + strconv.Itoa(int(k))
}

type impl struct {
	key []byte
}

func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k != KeySize {
		return nil, KeySizeError(k)
	}
	return impl{key: key}, nil
}

func (c impl) BlockSize() int {
	return BlockSize
}

func (c impl) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("fch: input not full block")
	}
	if len(dst) < BlockSize {
		panic("fch: output not full block")
	}
	// TODO: implement
	copy(dst[:BlockSize], src[:BlockSize])
}

func (c impl) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("fch: input not full block")
	}
	if len(dst) < BlockSize {
		panic("fch: output not full block")
	}
	// TODO: implement
	copy(dst[:BlockSize], src[:BlockSize])
}
