package cmd

import (
	"github.com/MeysamBavi/feistel-cipher-hw/internal/cmd/dec"
	"github.com/MeysamBavi/feistel-cipher-hw/internal/cmd/enc"
	"github.com/spf13/cobra"
	"os"
)

var key string

func Execute() {
	root := &cobra.Command{
		Use:   "fch",
		Short: "A simple Feistel based encryption algorithm",
	}
	root.PersistentFlags().StringVarP(
		&key,
		"key",
		"k",
		"",
		"The 64 bit key in hex format",
	)
	_ = root.MarkPersistentFlagRequired("key")
	root.AddCommand(enc.New(&key))
	root.AddCommand(dec.New(&key))
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
