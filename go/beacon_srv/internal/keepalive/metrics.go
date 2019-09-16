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
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/prom"
)

//bs_keepalive_receive_errs_total
//bs_keepalive_receive_msg_total
//bs_keepalive_transmit_errs_total
//bs_keepalive_transmit_msg_total

const (
	promNamespace = "bs_keepalive"
)

var (
	initOnce sync.Once

	outMsg *prometheus.CounterVec
	outErr *prometheus.CounterVec
	inMsg  *prometheus.CounterVec
	inErr  *prometheus.CounterVec
)

// InitMetrics initializes the metrics
func InitMetrics() {
	initOnce.Do(func() {
		labels := []string{"ifid"}
		outMsg = prom.NewCounterVec(promNamespace, "", "transmit_msgs_total",
			"Total number of transmitted keepalive msgs.", labels)
		outErr = prom.NewCounterVec(promNamespace, "", "transmit_err_total",
			"Total number of transmitted keepalive errors.", labels)
		inMsg = prom.NewCounterVec(promNamespace, "", "receive_msgs_total",
			"Total number of received keepalive msgs.", labels)
		inErr = prom.NewCounterVec(promNamespace, "", "receive_err_total",
			"Total number of received keepalive errors.", labels)

	})
}

func increaseTransmitMsgs(val string) {
	l := createReqLabels(val)
	outMsg.With(l).Inc()
}

func increaseTransmitErrors(val string) {
	l := createReqLabels(val)
	outErr.With(l).Inc()
}

func increaseReceiveMsgs(val string) {
	l := createReqLabels(val)
	inMsg.With(l).Inc()
}

func increaseReceiveErrors(val string) {
	l := createReqLabels(val)
	inErr.With(l).Inc()
}

func createReqLabels(val string) prometheus.Labels {
	return prometheus.Labels{
		"ifid": val,
	}
}
