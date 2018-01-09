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

// Example app for how an infrastructure service that does nothing except
// service some requests using default handlers.
//
// While the code compiles it does not do anything and is currently just
// included for reference purposes. It should not be part of the SCION codebase
// and will be removed.
package main

import (
	"io/ioutil"
	"net"
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/disp"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/xtest/p2p"
)

func main() {
	// Initialize test wires
	_, s2c := p2p.New()
	// Initialize networking and modules
	serverApp := InitDefaultNetworking(s2c)
	// Initialize Server
	serverApp.messenger.AddHandler("ChainRequest", serverApp.trustStore.NewChainReqHandler)
	serverApp.messenger.AddHandler("TRCRequest", serverApp.trustStore.NewTRCReqHandler)
	go serverApp.messenger.ListenAndServe()
	// Do work
	select {}
}

type ExampleServerApp struct {
	// Networking stack
	messenger infra.Messenger
	// Enabled modules
	trustStore *trust.Store
}

func InitDefaultNetworking(conn net.PacketConn) *ExampleServerApp {
	var err error
	server := &ExampleServerApp{}
	// Initialize transport
	transportLayer := transport.NewRUDP(conn, log.New("name", "server"))
	// Initialize message dispatcher
	dispatcherLayer := disp.New(transportLayer, messenger.DefaultAdapter, log.New("name", "server"))
	// Initialize TrustStore
	if server.trustStore, err = trust.NewStore(randomFileName(), log.Root()); err != nil {
		log.Error("Unable to create trust store", "err", err)
		os.Exit(-1)
	}
	// Initialize messenger with verification capabilities (trustStore-backed)
	server.messenger = messenger.New(dispatcherLayer, server.trustStore, log.Root())
	// Enable network access for trust store request handling
	server.trustStore.StartResolvers(server.messenger)
	return server
}

func randomFileName() string {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		panic("unable to create temp file")
	}
	name := file.Name()
	err = file.Close()
	if err != nil {
		panic("unable to close temp file")
	}
	return name
}
