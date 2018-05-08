package main

import (
	"flag"
	"log"
	"os"

	"github.com/scionproto/scion/go/examples/apna/cmd"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	local  snet.Addr
	remote snet.Addr
	mode   = flag.String("mode", "server", "Run in client or server mode")
)

func main() {
	flag.Parse()
	switch *mode {
	case "client":
		if remote.Host == nil {
			log.Fatal("Missing remote address")
			os.Exit(-1)
		}
		if remote.L4Port == 0 {
			log.Fatal("Invalid remote port", "remote port", remote.L4Port)
			os.Exit(-1)
		}
		cmd.StartClient(&local, &remote)
	case "server":
		cmd.StartServer(&local)
	}
}

func init() {
	flag.Var((*snet.Addr)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&remote), "remote", "(Mandatory for clients) address to connect to")
}
