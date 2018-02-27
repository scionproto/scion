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
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/proto"
)

const (
	DefaultRequestTimeout = 3 * time.Second
)

// API is a SCIOND API server running on top of a Transport.
type API struct {
	Transport transport.Transport

	// State for request handlers
	handlers *handlers
}

type handlers struct {
	PathRequest     PathRequestHandler
	ASInfoRequest   ASInfoRequestHandler
	IFInfoRequest   IFInfoRequestHandler
	SVCInfoRequest  SVCInfoRequestHandler
	RevNotification RevNotificationHandler
}

func (srv *API) Serve() error {
	// Initialize handler state if first time calling Serve
	if srv.handlers == nil {
		srv.handlers = &handlers{
			PathRequest: PathRequestHandler{
				Transport: srv.Transport,
			},
			ASInfoRequest: ASInfoRequestHandler{
				Transport: srv.Transport,
			},
			IFInfoRequest: IFInfoRequestHandler{
				Transport: srv.Transport,
			},
			SVCInfoRequest: SVCInfoRequestHandler{
				Transport: srv.Transport,
			},
			RevNotification: RevNotificationHandler{
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
	switch p.Which {
	case proto.SCIONDMsg_Which_pathReq:
		go srv.handlers.PathRequest.Handle(&p.PathReq, address)
	case proto.SCIONDMsg_Which_asInfoReq:
		go srv.handlers.ASInfoRequest.Handle(p.Id, &p.AsInfoReq, address)
	case proto.SCIONDMsg_Which_revNotification:
		go srv.handlers.RevNotification.Handle(&p.RevNotification, address)
	case proto.SCIONDMsg_Which_ifInfoRequest:
		go srv.handlers.IFInfoRequest.Handle(&p.IfInfoRequest, address)
	case proto.SCIONDMsg_Which_serviceInfoRequest:
		go srv.handlers.SVCInfoRequest.Handle(&p.ServiceInfoRequest, address)
	case proto.SCIONDMsg_Which_segTypeHopReq:
		log.Warn("unsupported seg type hop req")
	default:
		log.Error("unknown or unsupported capnp message")
	}
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
