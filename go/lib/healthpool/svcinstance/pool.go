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

// Package svcinstance provides a pool to keep track of the health status
// of service instances.
//
// Usage
//
// Instantiate the pool with a set of service instances. Use choose to
// select the best info according to the specified choosing algorithm. The
// caller should keep a reference to the returned Info and call Fail if an
// error is encountered during the request.
package svcinstance

import (
	"sync"

	"github.com/scionproto/scion/go/lib/healthpool"
	"github.com/scionproto/scion/go/lib/topology"
)

type infoMap map[string]*info

func (m infoMap) toSet() healthpool.InfoSet {
	infos := make(healthpool.InfoSet, len(m))
	for _, v := range m {
		infos[v] = struct{}{}
	}
	return infos
}

// Pool keeps track of the service instances information and their health
// status. It allows to choose service instances based on their health.
type Pool struct {
	mtx   sync.Mutex
	infos infoMap
	hpool *healthpool.Pool
}

// NewPool initializes the pool with the provided service instances and pool options.
func NewPool(svcInfo topology.IDAddrMap, opts healthpool.PoolOptions) (*Pool, error) {
	p := &Pool{
		infos: createMap(svcInfo, nil),
	}
	var err error
	if p.hpool, err = healthpool.NewPool(p.infos.toSet(), opts); err != nil {
		return nil, err
	}
	return p, nil
}

// Update updates the service instances in the pool. Instances in the pool
// that are not in svcInfo are removed. Instances in svcInfo that are not
// in the pool are added. Changed addresses of existing instances are
// updated. In that case, the fail count is reset to zero. However, if
// Options.AllowEmpty is not set, and the Update causes an empty pool, the
// instances are not replaced and an error is returned. If the pool is
// closed, an error is returned.
func (p *Pool) Update(svcInfo topology.IDAddrMap) error {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	infos := createMap(svcInfo, p.infos)
	if err := p.hpool.Update(infos.toSet()); err != nil {
		return err
	}
	p.infos = infos
	return nil
}

// Choose chooses the instance based on the configured algorithm. If the
// pool is closed, an error is returned.
func (p *Pool) Choose() (Info, error) {
	hinfo, err := p.hpool.Choose()
	if err != nil {
		return Info{}, err
	}
	return Info{info: hinfo.(*info)}, nil
}

// Close closes the pool. After closing the pool, Update and Choose will
// return errors. The pool is safe to being closed multiple times.
func (p *Pool) Close() {
	p.hpool.Close()
}

func createMap(svcInfo topology.IDAddrMap, oldInfos infoMap) infoMap {
	infos := make(infoMap, len(svcInfo))
	for k, svc := range svcInfo {
		if oldInfo, ok := oldInfos[k]; ok {
			infos[k] = oldInfo
			oldInfo.update(svc.PublicAddr(svc.Overlay))
		} else {
			infos[k] = &info{
				Info: healthpool.NewInfo(),
				addr: svc.PublicAddr(svc.Overlay),
				name: k,
			}
		}
	}
	return infos
}
