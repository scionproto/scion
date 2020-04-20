// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package integration

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/integration/progress"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

const (
	ModeServer       = "server"
	ModeClient       = "client"
	DefaultIOTimeout = 1 * time.Second
)

var (
	Local        snet.UDPAddr
	Mode         string
	Progress     string
	sciondAddr   string
	networksFile string
	Attempts     int
	logConsole   string
)

func Setup() {
	addFlags()
	validateFlags()
}

func addFlags() {
	flag.Var((*snet.UDPAddr)(&Local), "local", "(Mandatory) address to listen on")
	flag.StringVar(&Mode, "mode", ModeClient, "Run in "+ModeClient+" or "+ModeServer+" mode")
	flag.StringVar(&Progress, "progress", "", "Socket to write progress to")
	flag.StringVar(&sciondAddr, "sciond", sciond.DefaultSCIONDAddress, "SCIOND address")
	flag.StringVar(&networksFile, "networks", integration.SCIONDAddressesFile,
		"File containing network definitions")
	flag.IntVar(&Attempts, "attempts", 1, "Number of attempts before giving up")
	flag.StringVar(&logConsole, "log.console", "info",
		"Console logging level: trace|debug|info|warn|error|crit")
}

// InitTracer initializes the global tracer and returns a closer function.
func InitTracer(name string) (func(), error) {
	cfg := &env.Tracing{
		Enabled: true,
		Debug:   true,
	}
	cfg.InitDefaults()
	tr, closer, err := cfg.NewTracer(name)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tr)
	closeTracer := func() {
		if err := closer.Close(); err != nil {
			log.Error("Unable to close tracer", "err", err)
		}
	}
	return closeTracer, nil
}

func validateFlags() {
	flag.Parse()
	logCfg := log.Config{Console: log.ConsoleConfig{Level: logConsole}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	if Mode != ModeClient && Mode != ModeServer {
		LogFatal("Unknown mode, must be either '" + ModeClient + "' or '" + ModeServer + "'")
	}
	if Local.Host == nil {
		LogFatal("Missing local address")
	}
}

func InitNetwork() *snet.SCIONNetwork {
	ds := reliable.NewDispatcher("")
	sciondConn, err := sciond.NewService(sciondAddr).Connect(context.Background())
	if err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	n := snet.NewNetworkWithPR(Local.IA, ds, sciond.Querier{
		Connector: sciondConn,
		IA:        Local.IA,
	}, sciond.RevHandler{Connector: sciondConn})
	log.Debug("SCION network successfully initialized")
	return n
}

func SDConn() sciond.Connector {
	ctx, cancelF := context.WithTimeout(context.Background(), DefaultIOTimeout)
	defer cancelF()
	conn, err := sciond.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		LogFatal("Unable to initialize sciond connection", "err", err)
	}
	return conn
}

// AttemptFunc attempts a request repeatedly, receives the attempt number
type AttemptFunc func(n int) bool

// AttemptRepeatedly runs attempt until it returns true or more than Attempts were executed.
// Between two attempts at least RetryTimeout time has to pass.
// Returns 0 on success, 1 on failure.
func AttemptRepeatedly(name string, attempt AttemptFunc) int {
	attempts := 0
	for {
		attempts++
		if attempt(attempts) {
			return 0
		} else if attempts < Attempts {
			log.Info("Retrying...")
			time.Sleep(integration.RetryTimeout)
			continue
		}
		log.Error(fmt.Sprintf("%s failed. No more attempts...", name))
		break
	}
	return 1
}

// Done informs the integration test that a test binary has finished.
func Done(src, dst addr.IA) {
	if Progress == "" {
		return
	}
	if doneErr := (progress.Client{Socket: Progress}).Done(src, dst); doneErr != nil {
		log.Error("Unable to send done", "err", doneErr)
	}
}

// LogFatal logs a critical error and exits with 1
func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}
