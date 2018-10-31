// Copyright 2018 ETH Zurich
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
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	ModeServer       = "server"
	ModeClient       = "client"
	DefaultIOTimeout = 1 * time.Second
	RetryTimeout     = time.Second / 2
)

var (
	Local    snet.Addr
	Remote   snet.Addr
	Mode     string
	Sciond   string
	Attempts int
)

func Setup() {
	addFlags()
	validateFlags()
	defer log.LogPanicAndExit()
	initNetwork()
}

func addFlags() {
	flag.Var((*snet.Addr)(&Local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&Remote), "remote", "(Mandatory for clients) address to connect to")
	flag.StringVar(&Mode, "mode", ModeClient, "Run in "+ModeClient+" or "+ModeServer+" mode")
	flag.StringVar(&Sciond, "sciond", "", "Path to sciond socket")
	flag.IntVar(&Attempts, "attempts", 1, "Number of attempts before giving up")
	log.AddLogConsFlags()
}

func validateFlags() {
	flag.Parse()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	if Mode != ModeClient && Mode != ModeServer {
		LogFatal("Unknown mode, must be either '" + ModeClient + "' or '" + ModeServer + "'")
	}
	if Sciond == "" {
		Sciond = sciond.GetDefaultSCIONDPath(&Local.IA)
	}
	if Local.Host == nil {
		LogFatal("Missing local address")
	}
	if Mode == ModeClient {
		if Remote.Host == nil {
			LogFatal("Missing remote address")
		}
		if Remote.Host.L4 == nil {
			LogFatal("Missing remote port")
		}
		if Remote.Host.L4.Port() == 0 {
			LogFatal("Invalid remote port", "remote port", Remote.Host.L4.Port())
		}
	} else {
		if Local.Host.L4 == nil {
			LogFatal("Missing local port")
		}
		if Local.Host.L4.Port() == 0 {
			LogFatal("Invalid local port", "local port", Local.Host.L4.Port())
		}
	}
}

func initNetwork() {
	// Initialize default SCION networking context
	if err := snet.Init(Local.IA, Sciond, ""); err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	log.Debug("SCION network successfully initialized")
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}
