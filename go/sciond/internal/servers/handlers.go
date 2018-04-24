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

package servers

import (
	"context"
	"net"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/proto"
)

// PathRequestHandler represents the shared global state for the handling of all
// PathRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each PathRequest it receives.
type PathRequestHandler struct {
	// Path handling-specific data, e.g., reference to a path database
	Messenger messenger.Messenger

	// For local API traffic
	Transport infra.Transport
}

func (h *PathRequestHandler) Handle(pld *sciond.Pld, src net.Addr) {
	req := pld.PathReq
	log.Warn("unsupported path req", "req", req)
}

// ASInfoRequestHandler represents the shared global state for the handling of all
// ASInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each ASInfoRequest it receives.
type ASInfoRequestHandler struct {
	Transport infra.Transport
}

func (h *ASInfoRequestHandler) Handle(pld *sciond.Pld, src net.Addr) {
	_ = pld.AsInfoReq

	// FIXME(scrye): implement this correctly
	reply := &sciond.Pld{
		Id:    pld.Id,
		Which: proto.SCIONDMsg_Which_asInfoReply,
		AsInfoReply: sciond.ASInfoReply{
			Entries: []sciond.ASInfoReplyEntry{
				{
					RawIsdas: addr.IA{I: 1, A: 0xff0000000001}.IAInt(),
					Mtu:      1337,
					IsCore:   true,
				},
			},
		},
	}
	b, err := proto.PackRoot(reply)
	if err != nil {
		log.Error("unable to serialize SCIONDMsg reply")
	}
	h.Transport.SendMsgTo(context.Background(), b, src)
}

// IFInfoRequestHandler represents the shared global state for the handling of all
// IFInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each IFInfoRequest it receives.
type IFInfoRequestHandler struct {
	Transport infra.Transport
}

func (h *IFInfoRequestHandler) Handle(pld *sciond.Pld, src net.Addr) {
	req := pld.IfInfoRequest
	log.Warn("unsupported if info req", "req", req)
}

// SVCInfoRequestHandler represents the shared global state for the handling of all
// SVCInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each SVCInfoRequest it receives.
type SVCInfoRequestHandler struct {
	Transport infra.Transport
}

func (h *SVCInfoRequestHandler) Handle(pld *sciond.Pld, src net.Addr) {
	req := pld.ServiceInfoRequest
	log.Warn("unsupported svc info request", "req", req)
}

// RevNotificationHandler represents the shared global state for the handling of all
// RevNotification announcements. The SCIOND API spawns a goroutine with method Handle
// for each RevNotification it receives.
type RevNotificationHandler struct {
	Transport infra.Transport
}

func (h *RevNotificationHandler) Handle(pld *sciond.Pld, peer net.Addr) {
	req := pld.RevNotification
	log.Warn("unsupported rev notification", "req", req)
}
