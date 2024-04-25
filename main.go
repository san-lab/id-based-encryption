package main

import (
	"flag"

	"github.com/san-lab/id-based-encryption/client"
	"github.com/san-lab/id-based-encryption/tpkg"
)

func main() {
	mode := flag.String("mode", "client", "Mode: tpkg | client")
	flag.Parse()

	if *mode == "tpkg" {
		tpkg.Initialize()
		tpkg.StartServer()
	} else {
		client.StartServer()
	}
}
