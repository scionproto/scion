// Copyright 2026 ETH Zurich
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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet/squic/hummingbirdtest"
)

func main() {
	log.SetOutput(os.Stdout)
	if err := run(); err != nil {
		log.Fatalf("squic hummingbird acceptance helper failed: %v", err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("expected subcommand server or client")
	}
	switch os.Args[1] {
	case "server":
		return runServer(os.Args[2:])
	case "client":
		return runClient(os.Args[2:])
	default:
		return fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	var daemonAddr string
	var localAddr string
	var peerIARaw string
	var timeout time.Duration
	fs.StringVar(&daemonAddr, "daemon", "", "SCION daemon address")
	fs.StringVar(&localAddr, "local", "", "Local SCION UDP address")
	fs.StringVar(&peerIARaw, "peer-ia", "", "Remote IA used to derive the reply path")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "Server timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if daemonAddr == "" || localAddr == "" || peerIARaw == "" {
		return fmt.Errorf("server requires --daemon, --local, and --peer-ia")
	}

	local, err := hummingbirdtest.MustParseUDPAddr(localAddr)
	if err != nil {
		return err
	}
	peerIA, err := addr.ParseIA(peerIARaw)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return hummingbirdtest.RunServer(ctx, daemonAddr, local, peerIA, log.Printf)
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	var daemonAddr string
	var localAddr string
	var remoteAddr string
	var keysRoot string
	var timeout time.Duration
	fs.StringVar(&daemonAddr, "daemon", "", "SCION daemon address")
	fs.StringVar(&localAddr, "local", "", "Local SCION UDP address")
	fs.StringVar(&remoteAddr, "remote", "", "Remote SCION UDP address")
	fs.StringVar(&keysRoot, "keys-root", "", "Topology gen directory with AS keys")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "Client timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if daemonAddr == "" || localAddr == "" || remoteAddr == "" || keysRoot == "" {
		return fmt.Errorf("client requires --daemon, --local, --remote, and --keys-root")
	}

	local, err := hummingbirdtest.MustParseUDPAddr(localAddr)
	if err != nil {
		return err
	}
	remote, err := hummingbirdtest.MustParseUDPAddr(remoteAddr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return hummingbirdtest.RunClient(ctx, daemonAddr, local, remote, keysRoot, log.Printf)
}
