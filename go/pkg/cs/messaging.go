// Copyright 2020 Anapaya Systems
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

package cs

import (
	"context"
	"hash"
	"net"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/sock/reliable/reconnect"
)

// MACGenFactory creates a MAC factory
func MACGenFactory(configDir string) (func() hash.Hash, error) {
	mk, err := keyconf.LoadMaster(filepath.Join(configDir, "keys"))
	if err != nil {
		return nil, serrors.WrapStr("loading master key", err)
	}
	hfMacFactory, err := scrypto.HFMacFactory(mk.Key0)
	if err != nil {
		return nil, err
	}
	return hfMacFactory, nil
}

// NewOneHopConn registers a new connection that should be used with one hop
// paths.
func NewOneHopConn(ia addr.IA, pub *net.UDPAddr, disp string,
	reconnecting bool) (*snet.SCIONPacketConn, error) {

	dispatcherService := reliable.NewDispatcher(disp)
	if reconnecting {
		dispatcherService = reconnect.NewDispatcherService(dispatcherService)
	}
	pktDisp := &snet.DefaultPacketDispatcherService{
		Dispatcher: dispatcherService,
	}
	// We do not need to drain the connection, since the src address is spoofed
	// to contain the topo address.
	ohpAddress := snet.CopyUDPAddr(pub)
	ohpAddress.Port = 0
	conn, _, err := pktDisp.Register(context.Background(), ia, ohpAddress, addr.SvcNone)
	if err != nil {
		return nil, err
	}
	return conn.(*snet.SCIONPacketConn), nil
}
