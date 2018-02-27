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
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/transport"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/proto"
)

// PathRequestHandler represents the shared global state for the handling of all
// PathRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each PathRequest it receives.
type PathRequestHandler struct {
	// Path handling-specific data, e.g., reference to a path database

	// For network traffic (i.e., sending out path requests) include reference
	// to Messenger or maybe a throttler
	Messenger messenger.Messenger

	// For local API traffic
	Transport transport.Transport
}

func (h *PathRequestHandler) Handle(req *sciond.PathReq, peer net.Addr) {
	log.Warn("unsupported path req")
}

// ASInfoRequestHandler represents the shared global state for the handling of all
// ASInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each ASInfoRequest it receives.
type ASInfoRequestHandler struct {
	Transport transport.Transport
}

func (h *ASInfoRequestHandler) Handle(id uint64, req *sciond.ASInfoReq, peer net.Addr) {
	// FIXME(scrye): implement this correctly
	reply := &sciond.Pld{
		Id:    id,
		Which: proto.SCIONDMsg_Which_asInfoReply,
		AsInfoReply: sciond.ASInfoReply{
			Entries: []sciond.ASInfoReplyEntry{
				{
					RawIsdas: addr.IA{I: 1, A: 1}.IAInt(),
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
	h.Transport.SendMsgTo(context.Background(), b, peer)
}

// IFInfoRequestHandler represents the shared global state for the handling of all
// IFInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each IFInfoRequest it receives.
type IFInfoRequestHandler struct {
	Transport transport.Transport
}

func (h *IFInfoRequestHandler) Handle(req *sciond.IFInfoRequest, peer net.Addr) {
	log.Warn("unsupported if info req")
}

// SVCInfoRequestHandler represents the shared global state for the handling of all
// SVCInfoRequest queries. The SCIOND API spawns a goroutine with method Handle
// for each SVCInfoRequest it receives.
type SVCInfoRequestHandler struct {
	Transport transport.Transport
}

func (h *SVCInfoRequestHandler) Handle(req *sciond.ServiceInfoRequest, peer net.Addr) {
	log.Warn("unsupported svc info request")

}

// RevNotificationHandler represents the shared global state for the handling of all
// RevNotification announcements. The SCIOND API spawns a goroutine with method Handle
// for each RevNotification it receives.
type RevNotificationHandler struct {
	Transport transport.Transport
}

func (h *RevNotificationHandler) Handle(req *sciond.RevNotification, peer net.Addr) {
	log.Warn("unsupported rev notification")
}
