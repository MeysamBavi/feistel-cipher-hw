package fch

import (
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"slices"
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
	copy(dst[:BlockSize], src[:BlockSize])
	c.passThroughRounds(dst[:BlockSize], false)
}

func (c impl) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("fch: input not full block")
	}
	if len(dst) < BlockSize {
		panic("fch: output not full block")
	}
	copy(dst[:BlockSize], src[:BlockSize])
	c.passThroughRounds(dst[:BlockSize], true)
}

func (c impl) passThroughRounds(data []byte, reverse bool) {
	permuteBytes(data, ip, false)
	l := binary.BigEndian.Uint64(data[:BlockSize/2])
	r := binary.BigEndian.Uint64(data[BlockSize/2:])

	for _, k := range scheduleKeys(c.key, reverse) {
		newL := r
		r = l ^ roundFunction(r, k)
		l = newL
	}
	l, r = r, l

	data = data[:0]
	data = binary.BigEndian.AppendUint64(data, l)
	data = binary.BigEndian.AppendUint64(data, r)
	permuteBytes(data, ip, true)
}

func init() {
	r := rand.New(rand.NewSource(0))
	ip = r.Perm(128)
	keyPerm = r.Perm(64)
	sBox = r.Perm(256)
}

var ip []int

var keyPerm []int

var sBox []int

func permute(data uint64, p []int, reverse bool) uint64 {
	var result uint64 = 0
	for i, shift := range p {
		if reverse {
			shift, i = i, shift
		}
		d := (data >> i) & 1
		result |= d << shift
	}
	return result
}

func permuteBytes(data []byte, p []int, reverse bool) {
	result := make([]byte, len(data))
	for i, shift := range p {
		if reverse {
			shift, i = i, shift
		}
		d := (data[len(data)-1-i/8] >> (i % 8)) & 1
		result[len(data)-1-shift/8] |= d << (shift % 8)
	}
	copy(data, result)
}

func scheduleKeys(keyBytes []byte, reverse bool) []uint32 {
	key := permute(binary.BigEndian.Uint64(keyBytes), keyPerm, false)
	b := binary.BigEndian.AppendUint64(nil, key)
	result := []uint32{
		binary.BigEndian.Uint32([]byte{b[0] ^ b[4], b[1] ^ b[5], b[2] ^ b[4], b[3] ^ b[5]}),
		binary.BigEndian.Uint32([]byte{b[2] ^ b[6], b[3] ^ b[7], b[4] ^ b[6], b[5] ^ b[7]}),
		binary.BigEndian.Uint32([]byte{b[4] ^ b[0], b[5] ^ b[1], b[6] ^ b[0], b[7] ^ b[1]}),
		binary.BigEndian.Uint32([]byte{b[6] ^ b[2], b[7] ^ b[3], b[0] ^ b[2], b[1] ^ b[3]}),
	}
	if reverse {
		slices.Reverse(result)
	}
	return result
}

func roundFunction(r uint64, k uint32) uint64 {
	kk := uint64(k) | (uint64(k) << 32)
	r = kk ^ r
	b := binary.BigEndian.AppendUint64(nil, r)
	for i, v := range b {
		b[i] = byte(sBox[v])
	}
	return binary.BigEndian.Uint64(b)
}
