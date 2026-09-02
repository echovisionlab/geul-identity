package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/echovisionlab/geul-identity/internal/oathkeeperrules"
)

func main() {
	check := flag.Bool("check", false, "verify generated Oathkeeper rules match the checked-in rules file")
	flag.Parse()

	workingDirectory, err := os.Getwd()
	if err == nil {
		var root string
		root, err = oathkeeperrules.FindRepoRoot(workingDirectory)
		if err == nil {
			err = oathkeeperrules.Sync(root, *check)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
