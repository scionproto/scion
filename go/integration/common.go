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
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/scionproto/scion/go/lib/log"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
)

const (
	ModeServer = "server"
	ModeClient = "client"
)

var (
	Local   snet.Addr
	Remote  snet.Addr
	Mode    string
	Sciond  string
	Retries int
)

func init() {
	flag.Var((*snet.Addr)(&Local), "local", "(Mandatory) address to listen on")
	flag.Var((*snet.Addr)(&Remote), "remote", "(Mandatory for clients) address to connect to")
	flag.StringVar(&Mode, "mode", ModeClient, "Run in "+ModeClient+" or "+ModeServer+" mode")
	flag.StringVar(&Sciond, "sciond", "", "Path to sciond socket")
	flag.IntVar(&Retries, "retries", 0, "Number of retries before giving up")
	log.AddLogConsFlags()
	validateFlags()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s", err)
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()
	initNetwork()
}

func validateFlags() {
	flag.Parse()
	if Mode != ModeClient && Mode != ModeServer {
		LogFatal("Unknown mode, must be either '" + ModeClient + "' or '" + ModeServer + "'")
	}
	if Sciond == "" {
		Sciond = sd.GetDefaultSCIONDPath(&Local.IA)
	}
	if Local.Host == nil {
		LogFatal("Missing local address")
	}
	if Mode == ModeClient && Remote.Host == nil {
		LogFatal("Missing remote address")
	}
}

func initNetwork() {
	// Initialize default SCION networking context
	if err := snet.Init(Local.IA, Sciond, ""); err != nil {
		LogFatal("Unable to initialize SCION network", "err", err)
	}
	log.Debug("SCION network successfully initialized")
}

type Server interface {
	Run()
}

type Client interface {
	Run()
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}

func SetSignalHandler(closer io.Closer) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		closer.Close()
		os.Exit(1)
	}()
}
