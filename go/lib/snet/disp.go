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

package snet

import (
	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	liblog "github.com/netsec-ethz/scion/go/lib/log"
)

type DispPkt struct {
	B    common.RawBytes
	Addr *Addr
}

type DispatchFunc func(*DispPkt)

// XXX(kormat): N.B. the DispPkt is reused, applications should make a copy if this is a problem.
func PktDispatcher(c *Conn, f DispatchFunc) {
	defer liblog.LogPanicAndExit()
	var err error
	var l int
	dp := &DispPkt{B: make(common.RawBytes, common.MaxMTU)}
	for {
		dp.B = dp.B[:cap(dp.B)]
		l, dp.Addr, err = c.ReadFromSCION(dp.B)
		if err != nil {
			log.Error("PktDispatcher: Error reading from connection", "err", err)
			break
		}
		dp.B = dp.B[:l]
		f(dp)
	}
}
