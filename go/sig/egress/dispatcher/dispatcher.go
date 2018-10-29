// Copyright 2017 ETH Zurich
// Copyright 2018 ETH Zurich, Anapaya Systems
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

// Package dispatcher reads from input ring buffer, decides on a Session and
// puts data on the ring buffer of the Session.
package dispatcher

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/sig/egress"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
)

var _ egress.Runner = (*egressDispatcher)(nil)

type egressDispatcher struct {
	log.Logger
	ia               addr.IA
	ring             *ringbuf.Ring
	sessionSelector  egress.SessionSelector
	pktsRecvCounters map[metrics.CtrPairKey]metrics.CtrPair
}

func NewDispatcher(ia addr.IA, ring *ringbuf.Ring, ss egress.SessionSelector) *egressDispatcher {
	return &egressDispatcher{
		Logger:           log.New("ia", ia.String()),
		ring:             ring,
		sessionSelector:  ss,
		pktsRecvCounters: make(map[metrics.CtrPairKey]metrics.CtrPair),
	}
}

func (ed *egressDispatcher) Run() {
	ed.Info("EgressDispatcher: starting")
	bufs := make(ringbuf.EntryList, egress.EgressBufPkts)
	for {
		n, _ := ed.ring.Read(bufs, true)
		if n < 0 {
			break
		}
		for i := 0; i < n; i++ {
			buf := bufs[i].(common.RawBytes)
			sess := ed.sessionSelector.ChooseSess(buf)
			if sess == nil {
				// Release buffer back to free buffer pool
				egress.EgressFreePkts.Write(ringbuf.EntryList{buf}, true)
				// FIXME(kormat): replace with metric.
				ed.Debug("EgressDispatcher: unable to find session")
				continue
			}
			sess.Ring().Write(ringbuf.EntryList{buf}, true)
			ed.updateMetrics(sess.IA().IAInt(), sess.ID(), len(buf))
		}
	}
	ed.Info("EgressDispatcher: stopping")
}

func (ed *egressDispatcher) updateMetrics(remoteIA addr.IAInt, sessId mgmt.SessionType, read int) {
	key := metrics.CtrPairKey{RemoteIA: remoteIA, SessId: sessId}
	counters, ok := ed.pktsRecvCounters[key]
	if !ok {
		iaStr := remoteIA.IA().String()
		counters = metrics.CtrPair{
			Pkts:  metrics.PktsRecv.WithLabelValues(iaStr, sessId.String()),
			Bytes: metrics.PktBytesRecv.WithLabelValues(iaStr, sessId.String()),
		}
		ed.pktsRecvCounters[key] = counters
	}
	counters.Pkts.Inc()
	counters.Bytes.Add(float64(read))
}
