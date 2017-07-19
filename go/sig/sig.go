package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/inconshreveable/log15"

	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/sig/base"
	"github.com/netsec-ethz/scion/go/sig/control"
	"github.com/netsec-ethz/scion/go/sig/global"
	"github.com/netsec-ethz/scion/go/sig/management"
)

var (
	config = flag.String("config", "", "optional config file")
	cli    = flag.Bool("cli", false, "enable interactive console")
)

func main() {
	flag.Parse()
	liblog.Setup("sig")
	defer liblog.PanicLog()
	liblog.Flush()

	setupSignals()
	global.Init()

	sdb, err := base.NewSDB()
	if err != nil {
		log.Error("Failed to create SDB", "err", err)
		os.Exit(1)
	}

	// Enable static routing
	static := control.Static(sdb)

	// Launch data plane receiver
	go base.IngressWorker()

	// Load configuration file and/or start interactive console
	setupManagement(static)

	// If no console is up, block forever
	if *cli == false {
		select {}
	}
}

func setupManagement(static *control.StaticRP) {
	if *config == "" && *cli == false {
		log.Crit("Unable to start SIG without initial config and without interactive console.")
		os.Exit(1)
	}
	// Load config file (if specified) and start interactive console
	if *config != "" {
		management.RunConfig(static, *config)
	}
	if *cli {
		management.Run(static)
	}
}

func setupSignals() {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		s := <-sig
		log.Info("Received signal, exiting...", "signal", s)
		liblog.Flush()
		os.Exit(1)
	}()
}
