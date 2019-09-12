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

package keepalive

import (
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/prom"
)

const (
	promNamespace = "keepalive"
)

var (
	outKeepaliveMsg *prometheus.CounterVec

	initOnce sync.Once
)

// InitMetrics initializes the metrics
func InitMetrics() {
	initOnce.Do(func() {
		outKeepaliveMsg = prom.NewCounterVec(promNamespace, "", "out_msgs_total",
			"Total number of keepalive msgs.", []string{"x", "out_ifid"})
	})
}

func ifidToString(ifid common.IFIDType) string {
	return strconv.FormatUint(uint64(ifid), 10)
}
