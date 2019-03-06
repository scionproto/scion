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

// InfoSet is a set of infos.
type InfoSet map[Info]struct{}

// Pool holds entries and their health. It allows to choose entries based
// on their health.
type Pool struct {
	infosMtx sync.RWMutex
	infos    map[Info]Info
	choose   func() (Info, error)
	opts     PoolOptions
	expirer  *periodic.Runner
	closed   bool
}

// NewPool creates a health pool that contains all entries provided in infos.
func NewPool(infos map[Info]struct{}, opts PoolOptions) (*Pool, error) {
	p := &Pool{
		infos: make(map[Info]Info, len(infos)),
		opts:  opts,
	}
	if p.choose = opts.algorithm(p); p.choose == nil {
		return nil, common.NewBasicError("Invalid algorithm", nil, "algo", opts.Algorithm)
	}
	if err := p.Update(infos); err != nil {
		return nil, err
	}
	p.expirer = periodic.StartPeriodicTask((*expirer)(p), periodic.NewTicker(time.Second),
		time.Second)
	return p, nil
}

// Update updates the info entries in the pool. Entries in the pool that
// are not in infos are removed. Entries in infos that are not in the pool
// are added. However, if Options.AllowEmpty is not set, and the Update
// causes an empty pool, the entries are not replaced and an error is
// returned. If the pool is closed, an error is returned.
func (p *Pool) Update(infos map[Info]struct{}) error {
	if len(infos) == 0 && !p.opts.AllowEmpty {
		return common.NewBasicError("Info must contain entry", nil, "opts", p.opts)
	}
	p.infosMtx.Lock()
	defer p.infosMtx.Unlock()
	if p.closed {
		return common.NewBasicError(ErrPoolClosed, nil)
	}
	for info := range infos {
		p.infos[info] = info
	}
	// Remove infos that are no longer present.
	for info := range p.infos {
		if _, ok := infos[info]; !ok {
			delete(p.infos, info)
		}
	}
	return nil
}

// Choose chooses info based on the configured algorithm. If the pool is
// closed, an error is returned.
func (p *Pool) Choose() (Info, error) {
	p.infosMtx.RLock()
	defer p.infosMtx.RUnlock()
	if p.closed {
		return nil, common.NewBasicError(ErrPoolClosed, nil)
	}
	return p.choose()
}

// Close closes the pool and stops the periodic fail expiration. After
// closing the pool, Update and Choose will return errors. The pool is safe
// to being closed multiple times.
func (p *Pool) Close() {
	p.infosMtx.Lock()
	defer p.infosMtx.Unlock()
	if !p.closed {
		p.closed = true
		p.expirer.Stop()
	}
}

// chooseMinFails is a choosing algorithm which returns a info with minimum
// fail count.
func (p *Pool) chooseMinFails() (Info, error) {
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
type expirer Pool

func (e *expirer) Run(_ context.Context) {
	p := (*Pool)(e)
	p.infosMtx.RLock()
	defer p.infosMtx.RUnlock()
	now := time.Now()
	for _, info := range p.infos {
		info.expireFails(now, p.opts.Expire)
	}
}
