package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func Encrypt(block cipher.Block, plainText []byte) ([]byte, error) {
	plainText = PKCS7AddPadding(plainText, block.BlockSize())

	ivLen := block.BlockSize()
	cipherText := make([]byte, ivLen+len(plainText))
	iv := cipherText[:ivLen]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[ivLen:], plainText)
	return cipherText, nil
}

func Decrypt(block cipher.Block, cipherText []byte) ([]byte, error) {
	if len(cipherText) == 0 || len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("cipherText is not a multiple of the block size")
	}

	ivLen := block.BlockSize()
	iv := cipherText[:ivLen]
	plainText := make([]byte, len(cipherText)-ivLen)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainText, cipherText[ivLen:])
	return PKCS7TrimPadding(plainText)
}
