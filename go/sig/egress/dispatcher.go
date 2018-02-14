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

package egress

import (
	"io"
	"os"

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/sig/metrics"
	"github.com/scionproto/scion/go/sig/mgmt"
)

const (
	// FIXME(kormat): these relative sizes will fail if there are lots of egress dispatchers.
	egressFreePktsCap = 1024
	egressBufPkts     = 32
)

var (
	egressFreePkts *ringbuf.Ring
)

func Init() {
	egressFreePkts = ringbuf.New(egressFreePktsCap, func() interface{} {
		return make(common.RawBytes, common.MaxMTU)
	}, "egress", prometheus.Labels{"ringId": "freePkts", "sessId": ""})
}

type egressDispatcher struct {
	log.Logger
	devName          string
	devIO            io.ReadWriteCloser
	sess             *Session
	pktsRecvCounters map[metrics.CtrPairKey]metrics.CtrPair
}

func NewDispatcher(devName string, devIO io.ReadWriteCloser, sess *Session) *egressDispatcher {
	return &egressDispatcher{
		Logger:           log.New("dev", devName),
		devName:          devName,
		devIO:            devIO,
		sess:             sess,
		pktsRecvCounters: make(map[metrics.CtrPairKey]metrics.CtrPair),
	}
}

func (ed *egressDispatcher) Run() {
	defer liblog.LogPanicAndExit()
	ed.Info("EgressDispatcher: starting")
	bufs := make(ringbuf.EntryList, egressBufPkts)
	remoteIAInt := ed.sess.IA.IAInt()
BatchLoop:
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
				// Release buffer back to free buffer pool
				egressFreePkts.Write(ringbuf.EntryList{buf}, true)
				if err == io.EOF {
					// This dispatcher is shutting down
					break BatchLoop
				}
				// Sometimes we don't receive a clean EOF, so we check if the
				// tunnel device is closed.
				if pErr, ok := err.(*os.PathError); ok {
					if pErr.Err == os.ErrClosed {
						break BatchLoop
					}
				}
				ed.Error("EgressDispatcher: error reading from devIO", "err", err)
				continue
			}
			buf = buf[:length]
			sess := ed.chooseSess(buf)
			if sess == nil {
				// Release buffer back to free buffer pool
				egressFreePkts.Write(ringbuf.EntryList{buf}, true)
				// FIXME(kormat): replace with metric.
				ed.Debug("EgressDispatcher: unable to find session")
				continue
			}
			sess.ring.Write(ringbuf.EntryList{buf}, true)
			ed.updateMetrics(remoteIAInt, sess.SessId, length)
		}
	}
	ed.Info("EgressDispatcher: stopping")
}

func (ed *egressDispatcher) chooseSess(b common.RawBytes) *Session {
	return ed.sess
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
