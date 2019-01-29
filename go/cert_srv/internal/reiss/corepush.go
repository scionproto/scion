// Copyright 2019 Anapaya Systems
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

package reiss

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/messenger"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	// SleepAfterFailure is the base time to sleep after a failed attempt to push the chain.
	// The actual sleep time is: attempts * SleepAfterFailure.
	SleepAfterFailure = time.Second
)

var _ periodic.Task = (*CorePusher)(nil)

// CorePusher is a periodic.Task that pushes the local chain to all core CSes in the ISD.
// The interval this task is run in is expected to be rather large (e.g. 1h).
type CorePusher struct {
	LocalIA addr.IA
	TrustDB trustdb.TrustDB
	Msger   infra.Messenger
}

// Run makes sure all core CS have the chain of the local AS.
func (p *CorePusher) Run(ctx context.Context) {
	chain, err := p.TrustDB.GetChainMaxVersion(ctx, p.LocalIA)
	if err != nil {
		log.Error("[corePusher] Failed to get local chain from DB", "err", err)
		return
	}
	allCores, err := p.coreASes(ctx)
	if err != nil {
		log.Error("[corePusher] Failed to determine core ASes", "err", err)
		return
	}
	cores := allCores
	for syncTries := 0; syncTries < 3 && ctx.Err() == nil; syncTries++ {
		time.Sleep(time.Duration(syncTries) * SleepAfterFailure)
		cores, err = p.syncCores(ctx, chain, cores)
		if err == nil {
			log.Info("[corePusher] Successfully pushed chain to cores", "cores", len(allCores))
			return
		}
		log.Error("[corePusher] Failed to sync all cores", "err", err)
	}
}

// syncCores tries to sync to the given cores and returns the cores for which the syncing failed.
func (p *CorePusher) syncCores(ctx context.Context, chain *cert.Chain,
	cores []addr.IA) ([]addr.IA, error) {

	var checkErrors []addr.IA
	var remainingCores []addr.IA
	for _, coreIA := range cores {
		hasChain, err := p.hasChain(ctx, coreIA, chain)
		if err != nil {
			checkErrors = append(checkErrors, coreIA)
			// fall-through explicitly, we just assume the core doesn't have it and send it.
		}
		if !hasChain {
			if err = p.sendChain(ctx, coreIA, chain); err != nil {
				remainingCores = append(remainingCores, coreIA)
			}
		}
	}
	if len(checkErrors) > 0 || len(remainingCores) > 0 {
		return remainingCores, common.NewBasicError("Sync error", nil,
			"checkErrors", checkErrors, "remainingCores", remainingCores)
	}
	return nil, nil
}

func (p *CorePusher) coreASes(ctx context.Context) ([]addr.IA, error) {
	trc, err := p.TrustDB.GetTRCMaxVersion(ctx, p.LocalIA.I)
	if err != nil {
		return nil, common.NewBasicError("Unable to get TRC for local ISD", err)
	}
	return p.filterLocalIA(trc.CoreASes.ASList()), nil
}

func (p *CorePusher) filterLocalIA(allCores []addr.IA) []addr.IA {
	cores := make([]addr.IA, 0, len(allCores))
	for _, coreIA := range allCores {
		if !p.LocalIA.Equal(coreIA) {
			cores = append(cores, coreIA)
		}
	}
	return cores
}

func (p *CorePusher) hasChain(ctx context.Context, coreAS addr.IA,
	expectedChain *cert.Chain) (bool, error) {

	chainIA, ver := expectedChain.IAVer()
	req := &cert_mgmt.ChainReq{
		RawIA:     chainIA.IAInt(),
		Version:   ver,
		CacheOnly: true,
	}
	coreAddr := &snet.Addr{IA: coreAS, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	reply, err := p.Msger.GetCertChain(ctx, req, coreAddr, messenger.NextId())
	if err != nil {
		return false, common.NewBasicError("Error during fetch", err)
	}
	chain, err := reply.Chain()
	return chain != nil, err
}

func (p *CorePusher) sendChain(ctx context.Context, coreAS addr.IA, chain *cert.Chain) error {
	rawChain, err := chain.Compress()
	if err != nil {
		return common.NewBasicError("Failed to compress chain", err)
	}
	msg := &cert_mgmt.Chain{
		RawChain: rawChain,
	}
	coreAddr := &snet.Addr{IA: coreAS, Host: addr.NewSVCUDPAppAddr(addr.SvcCS)}
	// TODO(lukedirtwalker): Expect Acks.
	return p.Msger.SendCertChain(ctx, msg, coreAddr, messenger.NextId())
}
