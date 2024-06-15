package enc

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/MeysamBavi/feistel-cipher-hw/internal/crypt"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func New(key *string) *cobra.Command {
	return &cobra.Command{
		Use:   "enc",
		Short: "Encrypts the stdin content and prints out the result",
		RunE: func(cmd *cobra.Command, args []string) error {
			return main(*key)
		},
	}
}

func main(key string) error {
	k, err := hex.DecodeString(key)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	encrypted, err := crypt.Encrypt(block, data)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
	return nil
}
