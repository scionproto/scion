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

package disp

import (
	"fmt"
	"sync"

	log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/ctrl"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

func Init(conn *snet.Conn) {
	go snet.PktDispatcher(conn, dispFunc)
}

type RegType int

const (
	RegPollRep = iota
)

func (rt RegType) String() string {
	switch rt {
	case RegPollRep:
		return "RegPollRep"
	}
	return fmt.Sprintf("UNKNOWN (%d)", rt)
}

type RegPld struct {
	P    interface{}
	Addr *snet.Addr
}

type RegPldChan chan *RegPld

var (
	PollReqC   = make(RegPldChan, 1)
	Dispatcher = newDispReg(PollReqC)
)

type dispRegistry struct {
	sync.RWMutex
	pollReq RegPldChan
	pollRep map[string]RegPldChan
}

func newDispReg(defPollReq chan *RegPld) *dispRegistry {
	return &dispRegistry{
		pollReq: defPollReq,
		pollRep: make(map[string]RegPldChan),
	}
}

func (dm *dispRegistry) Register(regType RegType, key string, c RegPldChan) error {
	dm.Lock()
	defer dm.Unlock()
	switch regType {
	case RegPollRep:
		dm.pollRep[key] = c
	default:
		return common.NewCError("Register: Unsupported dispatcher RegType", "v", regType)
	}
	return nil
}

func (dm *dispRegistry) Unregister(regType RegType, key string) error {
	dm.Lock()
	defer dm.Unlock()
	switch regType {
	case RegPollRep:
		delete(dm.pollRep, key)
	default:
		return common.NewCError("Unregister: Unsupported dispatcher RegType", "v", regType)
	}
	return nil
}

func (dm *dispRegistry) sigCtrl(pld *mgmt.Pld, addr *snet.Addr) {
	dm.Lock()
	defer dm.Unlock()
	//log.Debug("Got sig ctrl packet", "pld", pld)
	u, err := pld.Union()
	if err != nil {
		log.Error("Unable to extract SIG ctrl union", "err", err, "src", addr)
		return
	}
	switch pld := u.(type) {
	case *mgmt.PollReq:
		dm.pollReq <- &RegPld{P: pld, Addr: addr}
	case *mgmt.PollRep:
		regPld := &RegPld{P: pld, Addr: addr}
		if pld.Addr == nil || pld.Addr.Ctrl == nil {
			log.Error("Incomplete SIG PollRep received", "src", addr, "pld", pld)
			return
		}
		entry, ok := dm.pollRep[MkRegPollKey(addr.IA, pld.Session)]
		if !ok {
			log.Warn("Unexpected SIG PollRep received", "src", addr, "pld", pld)
			return
		}
		entry <- regPld
	default:
		log.Error("Unsupported ctrl payload type", common.TypeOf(pld), "src", addr)
	}
}

func dispFunc(dp *snet.DispPkt) {
	cpld, err := ctrl.NewPldFromRaw(dp.B)
	if err != nil {
		log.Error("Unable to parse ctrl payload", "err", err, "src", dp.Addr)
		return
	}
	u, err := cpld.Union()
	if err != nil {
		log.Error("Unable to extract ctrl payload union", "err", err, "src", dp.Addr)
		return
	}
	//log.Debug("Got a packet", "type", common.TypeOf(u))
	switch pld := u.(type) {
	case *mgmt.Pld:
		Dispatcher.sigCtrl(pld, dp.Addr)
	default:
		log.Error("Unsupported ctrl payload type", common.TypeOf(pld))
	}
}

func MkRegPollKey(ia *addr.ISD_AS, session sigcmn.SessionType) string {
	return fmt.Sprintf("%s-%s", ia, session)
}
