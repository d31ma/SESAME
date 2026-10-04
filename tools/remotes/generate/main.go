package main

import (
	"fmt"
	"os"

	"github.com/d31ma/sesame/tools/remotes"
)

func main() {
	failure := remotes.NewGenerator(".").Write("remotes")
	if failure != nil {
		fmt.Fprintln(os.Stderr, failure)
		os.Exit(1)
	}
}
