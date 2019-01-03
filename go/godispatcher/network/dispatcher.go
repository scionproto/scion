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

package network

import (
	"net"

	"github.com/scionproto/scion/go/godispatcher/internal/registration"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

type Dispatcher struct {
	RoutingTable      registration.IATable
	OverlaySocket     string
	ApplicationSocket string
}

func (d *Dispatcher) ListenAndServe() error {
	overlayConn, err := net.ListenPacket("udp", d.OverlaySocket)
	if err != nil {
		return err
	}
	defer overlayConn.Close()

	appServerConn, err := reliable.Listen(d.ApplicationSocket)
	if err != nil {
		return err
	}
	defer appServerConn.Close()

	errChan := make(chan error)
	go func() {
		defer log.LogPanicAndExit()
		netToRingDataplane := &NetToRingDataplane{
			OverlayConn:  overlayConn,
			RoutingTable: d.RoutingTable,
		}
		errChan <- netToRingDataplane.Run()
	}()

	go func() {
		defer log.LogPanicAndExit()
		appServer := &AppSocketServer{
			Listener: appServerConn,
			ConnManager: &AppConnManager{
				RoutingTable: d.RoutingTable,
				OverlayConn:  overlayConn,
			},
		}
		errChan <- appServer.Serve()
	}()

	return <-errChan
}
