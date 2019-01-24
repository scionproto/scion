// Copyright 2018 Anapaya Systems
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

package cryptosyncer

import (
	"context"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/itopo"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

var _ periodic.Task = (*Syncer)(nil)

type Syncer struct {
	DB    trustdb.TrustDB
	Msger infra.Messenger
	IA    addr.IA
}

func (c *Syncer) Run(ctx context.Context) {
	cs, err := c.chooseServer()
	if err != nil {
		log.Error("[CryptoSync] Failed to select remote CS", "err", err)
		return
	}
	trcs, err := c.DB.GetAllTRCs(ctx)
	if err != nil {
		log.Error("[CryptoSync] Failed to read TRCs", "err", err)
		return
	}
	for i := range trcs {
		c.sendTRC(ctx, cs, trcs[i])
	}
	chains, err := c.DB.GetAllChains(ctx)
	if err != nil {
		log.Error("[CryptoSync] Failed to read chains", "err", err)
	}
	for i := range chains {
		c.sendChain(ctx, cs, chains[i])
	}
	log.Info("Sent crypto to CS", "cs", cs, "TRCs", len(trcs), "Chains", len(chains))
}

func (c *Syncer) chooseServer() (net.Addr, error) {
	topo := itopo.Get()
	svcInfo, err := topo.GetSvcInfo(proto.ServiceType_cs)
	if err != nil {
		return nil, err
	}
	topoAddr := svcInfo.GetAnyTopoAddr()
	if topoAddr == nil {
		return nil, common.NewBasicError("Failed to look up CS in topology", nil)
	}
	csAddr := topoAddr.PublicAddr(topo.Overlay)
	csOverlayAddr := topoAddr.OverlayAddr(topo.Overlay)
	return &snet.Addr{IA: c.IA, Host: csAddr, NextHop: csOverlayAddr}, nil
}

func (c *Syncer) sendTRC(ctx context.Context, cs net.Addr, trcObj *trc.TRC) {
	rawTRC, err := trcObj.Compress()
	if err != nil {
		log.Error("[CryptoSync] Failed to compress TRC for forwarding", "err", err)
		return
	}
	err = c.Msger.SendTRC(ctx, &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}, cs, messenger.NextId())
	if err != nil {
		log.Error("[CryptoSync] Failed to send TRC", "err", err)
	}
}

func (c *Syncer) sendChain(ctx context.Context, cs net.Addr, chain *cert.Chain) {
	rawChain, err := chain.Compress()
	if err != nil {
		log.Error("[CryptoSync] Failed to compress Chain for forwarding", "err", err)
		return
	}
	err = c.Msger.SendCertChain(ctx, &cert_mgmt.Chain{
		RawChain: rawChain,
	}, cs, messenger.NextId())
	if err != nil {
		log.Error("[CryptoSync] Failed to send Chain", "err", err)
	}
}
