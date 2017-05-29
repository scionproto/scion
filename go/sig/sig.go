package main

import (
	"flag"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/management"
)

const (
	Version = "0.0.1"
)

func main() {
	var config = flag.String("config", "", "optional config file")
	var sciond = flag.String("sciond", "/run/shm/sciond.sock", "SCIOND socket path")
	flag.Parse()

	// Create main SIG table
	sdb, err := base.NewSDB(*sciond)
	if err != nil {
		log.Error("Failed to create SDB", "err", err)
		return
	}

	// Enable static routing
	static := control.Static(sdb)

	// Launch data plane receiver
	go base.DataPlaneReceiver()

	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(Version, static, *config)
	}
	management.Run(Version, static)
}
