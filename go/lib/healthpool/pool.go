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

package healthpool

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/periodic"
)

// ErrPoolClosed is the error returned when operations on a closed pool are
// executed.
const ErrPoolClosed = "Pool closed"

var _ Pool = (*pool)(nil)

// pool is the Pool implementation.
type pool struct {
	infosMtx sync.RWMutex
	infos    InfoMap
	choose   func() (Info, error)
	opts     PoolOptions
	expirer  *periodic.Runner
	closed   bool
}

// NewPool creates a health pool that contains all entries provided in infos.
func NewPool(infos InfoMap, opts PoolOptions) (Pool, error) {
	p := &pool{
		infos: make(InfoMap, len(infos)),
		opts:  opts,
	}
	switch opts.algorithm() {
	case MinFailCount:
		p.choose = p.chooseMinFails
	default:
		return nil, common.NewBasicError("Invalid algorithm", nil, "algo", opts.algorithm())
	}
	if err := p.Update(infos); err != nil {
		return nil, err
	}
	p.expirer = periodic.StartPeriodicTask((*expirer)(p), periodic.NewTicker(time.Second),
		time.Second)
	return p, nil
}

func (p *pool) Update(infos InfoMap) error {
	if len(infos) == 0 && !p.opts.AllowEmpty {
		return common.NewBasicError("Info must contain entry", nil, "opts", p.opts)
	}
	p.infosMtx.Lock()
	defer p.infosMtx.Unlock()
	if p.closed {
		return common.NewBasicError(ErrPoolClosed, nil)
	}
	for k, info := range infos {
		p.infos[k] = info
	}
	// Remove infos that are no longer present.
	for k := range p.infos {
		if _, ok := infos[k]; !ok {
			delete(p.infos, k)
		}
	}
	return nil
}

func (p *pool) Choose() (Info, error) {
	p.infosMtx.RLock()
	defer p.infosMtx.RUnlock()
	if p.closed {
		return nil, common.NewBasicError(ErrPoolClosed, nil)
	}
	return p.choose()
}

func (p *pool) Close() {
	p.expirer.Stop()
}

// chooseMinFails is a choosing algorithm which returns a info with minimum
// fail count.
func (p *pool) chooseMinFails() (Info, error) {
	var best Info
	var minFail = -1
	for _, info := range p.infos {
		failCount := info.FailCount()
		if minFail == -1 || failCount < minFail {
			best = info
			minFail = failCount
		}
	}
	if best == nil {
		return nil, common.NewBasicError("Unable to find an info instance", nil)
	}
	return best, nil
}

// expirer is a wrapper to implement period.Task.
type expirer pool

func (e *expirer) Run(_ context.Context) {
	p := (*pool)(e)
	p.infosMtx.RLock()
	defer p.infosMtx.RUnlock()
	now := time.Now()
	for _, info := range p.infos {
		info.expireFails(now, p.opts.Expire)
	}
}
