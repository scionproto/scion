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

// Package servers contains the logic for creating and managing SCIOND API
// servers. It currently supports listening on ReliableSocket and UNIX Domain
// socket (in unixgram mode).
package servers

import (
	"bytes"
	"context"
	"net"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/proto"
)

const (
	DefaultRequestTimeout = 3 * time.Second
)

// API is a SCIOND API server running on top of a Transport.
type API struct {
	Transport infra.Transport

	// State for request handlers
	handlers map[proto.SCIONDMsg_Which]handler
}

type handler interface {
	Handle(pld *sciond.Pld, src net.Addr)
}

func (srv *API) Serve() error {
	// Initialize handler state if first time calling Serve
	if srv.handlers == nil {
		srv.handlers = map[proto.SCIONDMsg_Which]handler{
			proto.SCIONDMsg_Which_pathReq: &PathRequestHandler{
				Transport: srv.Transport,
			},
			proto.SCIONDMsg_Which_asInfoReq: &ASInfoRequestHandler{
				Transport: srv.Transport,
			},
			proto.SCIONDMsg_Which_ifInfoRequest: &IFInfoRequestHandler{
				Transport: srv.Transport,
			},
			proto.SCIONDMsg_Which_serviceInfoRequest: &SVCInfoRequestHandler{
				Transport: srv.Transport,
			},
			proto.SCIONDMsg_Which_revNotification: &RevNotificationHandler{
				Transport: srv.Transport,
			},
		}
	}

	for {
		b, address, err := srv.Transport.RecvFrom(context.Background())
		if err != nil {
			return err
		}
		go func() {
			srv.Handle(b, address)
		}()
	}
}

func (srv *API) Handle(b common.RawBytes, address net.Addr) {
	p := &sciond.Pld{}
	if err := proto.ParseFromReader(p, proto.SCIONDMsg_TypeID, bytes.NewReader(b)); err != nil {
		log.Error("capnp error", "err", err)
		return
	}
	go srv.handlers[p.Which].Handle(p, address)
}

func (srv *API) Close() error {
	// FIXME(scrye): propagate correct contexts
	return srv.Transport.Close(context.TODO())
}

// Shutdown cleanly stops the server from handling future requests, while
// allowing pending requests to finish.
func (srv *API) Shutdown() error {
	panic("not implemented")
}
