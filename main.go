package main

import (
	"os"

	"github.com/andpalmier/tfox/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
