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
	"github.com/netsec-ethz/scion/go/lib/pktdisp"
	"github.com/netsec-ethz/scion/go/lib/snet"
	"github.com/netsec-ethz/scion/go/sig/mgmt"
	"github.com/netsec-ethz/scion/go/sig/sigcmn"
)

func Init(conn *snet.Conn) {
	go pktdisp.PktDispatcher(conn, dispFunc)
}

type RegType int

const (
	RegPollRep RegType = iota
)

func (rt RegType) String() string {
	switch rt {
	case RegPollRep:
		return "RegPollRep"
	}
	return fmt.Sprintf("UNKNOWN (%d)", rt)
}

type RegPld struct {
	Id   mgmt.MsgIdType
	P    interface{}
	Addr *snet.Addr
}

type RegPldChan chan *RegPld

var (
	Dispatcher = newDispReg()
)

type dispRegistry struct {
	sync.RWMutex
	PollReqC RegPldChan
	pollRep  map[RegPollKey]RegPldChan
}

func newDispReg() *dispRegistry {
	return &dispRegistry{
		PollReqC: make(RegPldChan, 16),
		pollRep:  make(map[RegPollKey]RegPldChan),
	}
}

func (dm *dispRegistry) Register(regType RegType, key RegPollKey, c RegPldChan) error {
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

func (dm *dispRegistry) Unregister(regType RegType, key RegPollKey) error {
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
	u, err := pld.Union()
	if err != nil {
		log.Error("Unable to extract SIG ctrl union", "err", err, "src", addr)
		return
	}
	msgId := pld.Id
	switch pld := u.(type) {
	case *mgmt.PollReq:
		dm.PollReqC <- &RegPld{Id: msgId, P: pld, Addr: addr}
	case *mgmt.PollRep:
		regPld := &RegPld{Id: msgId, P: pld, Addr: addr}
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

func dispFunc(dp *pktdisp.DispPkt) {
	scpld, err := ctrl.NewSignedPldFromRaw(dp.Raw)
	src := dp.Addr.Copy()
	if err != nil {
		log.Error("Unable to parse signed ctrl payload", "err", err, "src", src)
		return
	}
	cpld, err := scpld.Pld()
	if err != nil {
		log.Error("Unable to parse ctrl payload", "err", err, "src", src)
		return
	}
	u, err := cpld.Union()
	if err != nil {
		log.Error("Unable to extract ctrl payload union", "err", err, "src", src)
		return
	}
	switch pld := u.(type) {
	case *mgmt.Pld:
		Dispatcher.sigCtrl(pld, src)
	default:
		log.Error("Unsupported ctrl payload type", common.TypeOf(pld))
	}
}

type RegPollKey string

func MkRegPollKey(ia *addr.ISD_AS, session sigcmn.SessionType) RegPollKey {
	return RegPollKey(fmt.Sprintf("%s-%s", ia, session))
}
