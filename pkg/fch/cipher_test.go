package fch

import (
	"crypto/rand"
	"fmt"
	"github.com/MeysamBavi/feistel-cipher-hw/internal/crypt"
	"io"
	rand2 "math/rand"
	"testing"
)

func TestSame(t *testing.T) {
	const data = "AB"
	key := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}

	block, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypt.Encrypt(block, []byte(data))
	if err != nil {
		t.Fatal("encryption failed:", err)
	}
	decrypted, err := crypt.Decrypt(block, encrypted)
	if err != nil {
		t.Fatal("decryption failed:", err)
	}
	if string(decrypted) != data {
		t.Error("decrypted data has changed:", string(decrypted))
	}
}

func TestPermute(t *testing.T) {
	data := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}
	a := fmt.Sprint(data)
	perm := rand2.Perm(128)
	permuteBytes(data, perm, false)
	permuteBytes(data, perm, true)
	b := fmt.Sprint(data)
	if a != b {
		t.Error("permute not reversible:", b)
	}
}
