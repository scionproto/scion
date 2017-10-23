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

	log "github.com/inconshreveable/log15"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
	"github.com/netsec-ethz/scion/go/lib/ringbuf"
	"github.com/netsec-ethz/scion/go/sig/metrics"
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
	devName string
	devIO   io.ReadWriteCloser
	sess    *Session
}

func NewDispatcher(devName string, devIO io.ReadWriteCloser, sess *Session) *egressDispatcher {
	return &egressDispatcher{
		Logger:  log.New("dev", devName),
		devName: devName,
		devIO:   devIO,
		sess:    sess,
	}
}

func (ed *egressDispatcher) Run() {
	defer liblog.LogPanicAndExit()
	ed.Info("EgressDispatcher: starting")
	bufs := make(ringbuf.EntryList, egressBufPkts)
	pktsRecv := metrics.PktsRecv.WithLabelValues(ed.devName)
	pktBytesRecv := metrics.PktBytesRecv.WithLabelValues(ed.devName)
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
				ed.Error("EgressDispatcher: error reading from devIO", "err", err)
				continue
			}
			buf = buf[:length]
			sess := ed.chooseSess(buf)
			if sess == nil {
				// FIXME(kormat): replace with metric.
				log.Debug("Unable to find session")
				continue
			}
			sess.ring.Write(ringbuf.EntryList{buf}, true)
			pktsRecv.Inc()
			pktBytesRecv.Add(float64(length))
		}
	}
	ed.Info("EgressDispatcher: stopping")
}

func (ed *egressDispatcher) chooseSess(b common.RawBytes) *Session {
	return ed.sess
}
