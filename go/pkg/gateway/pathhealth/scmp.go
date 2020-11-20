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

package pathhealth

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

type traceroutePkt struct {
	Remote     addr.IA
	Identifier uint16
	Sequence   uint16
}

type scmpHandler struct {
	wrappedHandler snet.SCMPHandler
	pkts           chan<- traceroutePkt
}

func (h scmpHandler) Handle(pkt *snet.Packet) error {
	if pkt.Payload == nil {
		return serrors.New("no payload found")
	}
	tr, ok := pkt.Payload.(snet.SCMPTracerouteReply)
	if !ok {
		return h.wrappedHandler.Handle(pkt)
	}
	h.pkts <- traceroutePkt{
		Remote:     pkt.Source.IA,
		Identifier: tr.Identifier,
		Sequence:   tr.Sequence,
	}
	return nil
}
