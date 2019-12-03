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
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ periodic.Task = (*Syncer)(nil)

type Syncer struct {
	DB    trustdb.TrustDB
	Msger infra.Messenger
	IA    addr.IA
}

func (c *Syncer) Name() string {
	return "ps_cryptosyncer_syncer"
}

func (c *Syncer) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	trcChan, err := c.DB.GetAllTRCs(ctx)
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to read TRCs", "err", err)
		return
	}
	cs := snet.NewSVCAddr(c.IA, nil, nil, addr.SvcCS)
	trcCount := c.sendTRCs(ctx, trcChan, cs)
	chainChan, err := c.DB.GetAllChains(ctx)
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to read chains", "err", err)
	}
	chainCount := c.sendChains(ctx, chainChan, cs)
	logger.Info("Sent crypto to CS", "cs", cs, "TRCs", trcCount, "Chains", chainCount)
}

func (c *Syncer) sendTRCs(ctx context.Context, trcChan <-chan trustdb.TrcOrErr, cs net.Addr) int {
	logger := log.FromCtx(ctx)
	trcCount := 0
	for r := range trcChan {
		if r.Err != nil {
			logger.Error("[cryptosyncer.Syncer] Error while reading all TRCs", "err", r.Err)
		} else {
			c.sendTRC(ctx, cs, r.TRC)
			trcCount++
		}
	}
	return trcCount
}

func (c *Syncer) sendTRC(ctx context.Context, cs net.Addr, trcObj *trc.TRC) {
	logger := log.FromCtx(ctx)
	rawTRC, err := trcObj.Compress()
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to compress TRC for forwarding", "err", err)
		return
	}
	err = c.Msger.SendTRC(ctx, &cert_mgmt.TRC{
		RawTRC: rawTRC,
	}, cs, messenger.NextId())
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to send TRC", "err", err, "cs", cs)
	}
}

func (c *Syncer) sendChains(ctx context.Context,
	chainChan <-chan trustdb.ChainOrErr, cs net.Addr) int {

	logger := log.FromCtx(ctx)
	chainCount := 0
	for r := range chainChan {
		if r.Err != nil {
			logger.Error("[cryptosyncer.Syncer] Error while reading all Chains", "err", r.Err)
		} else {
			c.sendChain(ctx, cs, r.Chain)
			chainCount++
		}
	}
	return chainCount
}

func (c *Syncer) sendChain(ctx context.Context, cs net.Addr, chain *cert.Chain) {
	logger := log.FromCtx(ctx)
	rawChain, err := chain.Compress()
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to compress Chain for forwarding", "err", err)
		return
	}
	err = c.Msger.SendCertChain(ctx, &cert_mgmt.Chain{
		RawChain: rawChain,
	}, cs, messenger.NextId())
	if err != nil {
		logger.Error("[cryptosyncer.Syncer] Failed to send Chain", "err", err, "cs", cs)
	}
}
