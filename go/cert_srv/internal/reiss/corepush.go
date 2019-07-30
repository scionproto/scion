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
	"sync"
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
	// DefaultTryTimeout is the default timeout for one sync try if the context
	// has no deadline set.
	DefaultTryTimeout = 20 * time.Second
)

var _ periodic.Task = (*CorePusher)(nil)

// CorePusher is a periodic.Task that pushes the local chain to all core CSes in the ISD.
// The interval this task is run in is expected to be rather large (e.g. 1h).
type CorePusher struct {
	LocalIA addr.IA
	TrustDB trustdb.TrustDB
	Msger   infra.Messenger
}

// Name returns the tasks name.
func (p *CorePusher) Name() string {
	return "reiss.CorePusher"
}

// Run makes sure all core CS have the chain of the local AS.
func (p *CorePusher) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	chain, err := p.TrustDB.GetChainMaxVersion(ctx, p.LocalIA)
	if err != nil {
		logger.Error("[reiss.CorePusher] Failed to get local chain from DB", "err", err)
		return
	}
	cores, err := p.coreASes(ctx)
	if err != nil {
		logger.Error("[reiss.CorePusher] Failed to determine core ASes", "err", err)
		return
	}
	numCores := len(cores.ias)
	tryTimeout := DefaultTryTimeout
	if deadline, ok := ctx.Deadline(); ok {
		tryTimeout = deadline.Sub(time.Now()) / 3
	}
	for syncTries := 0; syncTries < 3 && ctx.Err() == nil; syncTries++ {
		tryCtx, cancelF := context.WithTimeout(ctx, tryTimeout)
		err = p.syncCores(tryCtx, chain, cores)
		cancelF()
		if err == nil {
			logger.Info("[reiss.CorePusher] Successfully pushed chain to cores", "cores", numCores)
			return
		}
		logger.Error("[reiss.CorePusher] Failed to sync all cores", "err", err)
		select {
		case <-time.After(time.Duration(syncTries+1) * SleepAfterFailure):
		case <-ctx.Done():
		}
	}
}

func (p *CorePusher) coreASes(ctx context.Context) (*iaMap, error) {
	trc, err := p.TrustDB.GetTRCMaxVersion(ctx, p.LocalIA.I)
	if err != nil {
		return nil, common.NewBasicError("Unable to get TRC for local ISD", err)
	}
	cores := make(map[addr.IA]struct{})
	for _, ia := range trc.CoreASes.ASList() {
		if !p.LocalIA.Equal(ia) {
			cores[ia] = struct{}{}
		}
	}
	return &iaMap{ias: cores}, nil
}

// syncCores tries to sync to the given cores and returns the cores for which the syncing failed.
func (p *CorePusher) syncCores(ctx context.Context, chain *cert.Chain, cores *iaMap) error {

	wg := &sync.WaitGroup{}
	wg.Add(len(cores.ias))
	checkErrs := &iaList{}
	for coreIA := range cores.ias {
		p.asyncPush(ctx, chain, cores, coreIA, checkErrs, wg)
	}
	wg.Wait()
	if len(checkErrs.ias) > 0 || len(cores.ias) > 0 {
		return common.NewBasicError("Sync error", nil, "checkErrors", checkErrs.ias,
			"remainingCores", cores.list())
	}
	return nil
}

// asyncPush pushes the certificate chain to the core if it does not have it already.
func (p *CorePusher) asyncPush(ctx context.Context, chain *cert.Chain, cores *iaMap,
	core addr.IA, checkErrs *iaList, wg *sync.WaitGroup) {

	go func() {
		defer log.LogPanicAndExit()
		defer wg.Done()
		hasChain, err := p.hasChain(ctx, core, chain)
		if err != nil {
			checkErrs.append(core)
			// fall-through explicitly, we just assume the core doesn't have it and send it.
		}
		var sendErr error
		if !hasChain {
			sendErr = p.sendChain(ctx, core, chain)
		}
		if sendErr == nil {
			cores.delete(core)
		}
	}()
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

type iaList struct {
	mu  sync.Mutex
	ias []addr.IA
}

func (l *iaList) append(ia addr.IA) {
	l.mu.Lock()
	l.ias = append(l.ias, ia)
	l.mu.Unlock()
}

type iaMap struct {
	mu  sync.Mutex
	ias map[addr.IA]struct{}
}

func (m *iaMap) delete(ia addr.IA) {
	m.mu.Lock()
	delete(m.ias, ia)
	m.mu.Unlock()
}

func (m *iaMap) list() []addr.IA {
	m.mu.Lock()
	l := make([]addr.IA, 0, len(m.ias))
	for ia := range m.ias {
		l = append(l, ia)
	}
	m.mu.Unlock()
	return l
}
