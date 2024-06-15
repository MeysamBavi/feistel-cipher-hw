package dec

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
		Use:   "dec",
		Short: "Decrypts the stdin content and prints out the result",
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
	dataBase64, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	data := make([]byte, base64.URLEncoding.DecodedLen(len(dataBase64)))
	n, err := base64.URLEncoding.Decode(data, dataBase64)
	if err != nil {
		return err
	}
	data = data[:n]
	decrypted, err := crypt.Decrypt(block, data)
	if err != nil {
		return err
	}
	fmt.Printf("%s", decrypted)
	return nil
}
