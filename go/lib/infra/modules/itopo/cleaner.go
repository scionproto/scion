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

package itopo

import (
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
)

var _ periodic.Task = cleaner{}

// StartCleaner starts a periodic task that removes expired dynamic topologies.
func StartCleaner(tick, timeout time.Duration) *periodic.Runner {
	return periodic.StartPeriodicTask(cleaner{}, periodic.NewTicker(tick), timeout)
}

type cleaner struct{}

// Run deletes expired dynamic topologies and calls the dropFunc passed to Init.
func (c cleaner) Run(ctx context.Context) {
	st.Lock()
	defer st.Unlock()
	if st.topo.dynamic != nil && !st.topo.dynamic.Active(time.Now()) {
		log.Info("[itopo.Cleaner] Dropping expired dynamic topology",
			"ts", st.topo.dynamic.Timestamp, "ttl", st.topo.dynamic.TTL,
			"expired", st.topo.dynamic.Expiry())
		st.topo.dynamic = nil
		call(st.clbks.DropDynamic)
	}
}
