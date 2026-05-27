package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dogadmin/jsscango/internal/cli"
)

var version = "dev"

func main() {
	root := cli.NewRoot(version)
	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
