// Copyright 2017 ETH Zurich
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

package base

import (
	"io"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/sig/metrics"
)

const (
	egressFreePktsCap = 1024
)

var (
	egressFreePkts *ringbuf.Ring
)

func Init() {
	egressFreePkts = ringbuf.New(egressFreePktsCap, func() interface{} {
		return make(common.RawBytes, 1<<16)
	}, "egress", prometheus.Labels{"ringId": "freeFrames"})
}

type egressDispatcher struct {
	devName string
	devIO   io.ReadWriteCloser
	spp     *SyncPathPolicies
}

func newEgressDispatcher(devName string, devIO io.ReadWriteCloser,
	spp *SyncPathPolicies) *egressDispatcher {
	return &egressDispatcher{devName: devName, devIO: devIO, spp: spp}
}

func (ed *egressDispatcher) Run() {
	defer liblog.LogPanicAndExit()
	bufs := make(ringbuf.EntryList, 32)
	pktsRecv := metrics.PktsRecv.WithLabelValues(ed.devName)
	pktBytesRecv := metrics.PktBytesRecv.WithLabelValues(ed.devName)
	pps := ed.spp.Load()
	var pp *PathPolicy
	for _, pp = range pps {
		break
	}
	for {
		n, _ := egressFreePkts.Read(bufs, true)
		if n < 0 {
			break
		}
		for i := 0; i < n; i++ {
			buf := bufs[i].(common.RawBytes)
			bufs[i] = nil
			buf = buf[:cap(buf)]
			length, err := ed.devIO.Read(buf)
			if err != nil {
				log.Error("EgressDispatcher: error reading from devIO",
					"dev", ed.devName, "err", err)
				continue
			}
			buf = buf[:length]
			pp.ring.Write(ringbuf.EntryList{buf}, true)
			pktsRecv.Inc()
			pktBytesRecv.Add(float64(length))
		}
	}
	log.Info("EgressDispatcher: stopping", "dev", ed.devName)
}
