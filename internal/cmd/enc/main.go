package enc

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/MeysamBavi/feistel-cipher-hw/internal/crypt"
	"github.com/MeysamBavi/feistel-cipher-hw/pkg/fch"
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
	block, err := fch.NewCipher(k)
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
	fmt.Println(base64.URLEncoding.EncodeToString(encrypted))
	return nil
}
