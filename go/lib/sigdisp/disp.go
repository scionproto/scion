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

package sigdisp

import (
	"fmt"
	"sync"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/sig_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/pktdisp"
	"github.com/scionproto/scion/go/lib/snet"
)

func Init(conn *snet.Conn, useid bool) {
	useID = useid
	go func() {
		defer log.HandlePanic()
		pktdisp.PktDispatcher(conn, dispFunc, nil)
	}()
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
	Id   sig_mgmt.MsgIdType
	P    interface{}
	Addr *snet.UDPAddr
}

type RegPldChan chan *RegPld

var (
	Dispatcher = newDispReg()
	useID      bool
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
		return common.NewBasicError("Register: Unsupported dispatcher RegType", nil, "v", regType)
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
		return common.NewBasicError("Unregister: Unsupported dispatcher RegType", nil, "v", regType)
	}
	return nil
}

func (dm *dispRegistry) sigCtrl(pld *sig_mgmt.Pld, addr *snet.UDPAddr) {
	dm.Lock()
	defer dm.Unlock()
	u, err := pld.Union()
	if err != nil {
		log.Error("Unable to extract SIG ctrl union", "src", addr, "err", err)
		return
	}
	msgId := pld.Id
	switch pld := u.(type) {
	case *sig_mgmt.PollReq:
		dm.PollReqC <- &RegPld{Id: msgId, P: pld, Addr: addr}
	case *sig_mgmt.PollRep:
		regPld := &RegPld{Id: msgId, P: pld, Addr: addr}
		if pld.Addr == nil || pld.Addr.Ctrl == nil {
			log.Error("Incomplete SIG PollRep received", "src", addr, "pld", pld)
			return
		}
		entry, ok := dm.pollRep[MkRegPollKey(addr.IA, pld.Session, msgId)]
		if !ok {
			log.Warn("Unexpected SIG PollRep received", "src", addr, "pld", pld)
			return
		}
		entry <- regPld
	default:
		log.Error("Unsupported ctrl payload type", "type", common.TypeOf(pld), "src", addr)
	}
}

func dispFunc(dp *pktdisp.DispPkt) {
	scpld, err := ctrl.NewSignedPldFromRaw(dp.Raw)
	var src *snet.UDPAddr
	switch v := dp.Addr.(type) {
	case *snet.UDPAddr:
		src = &snet.UDPAddr{
			IA:      v.IA,
			Path:    v.Path.Copy(),
			NextHop: snet.CopyUDPAddr(v.NextHop),
			Host:    snet.CopyUDPAddr(v.Host),
		}
	default:
		log.Error("Not valid snet address")
		return
	}
	if err != nil {
		log.Error("Unable to parse signed ctrl payload", "src", src, "err", err)
		return
	}
	cpld, err := scpld.UnsafePld()
	if err != nil {
		log.Error("Unable to parse ctrl payload", "src", src, "err", err)
		return
	}
	u, err := cpld.Union()
	if err != nil {
		log.Error("Unable to extract ctrl payload union", "src", src, "err", err)
		return
	}
	switch pld := u.(type) {
	case *sig_mgmt.Pld:
		Dispatcher.sigCtrl(pld, src)
	default:
		log.Error("Unsupported ctrl payload type", "type", common.TypeOf(pld))
	}
}

type RegPollKey string

func MkRegPollKey(ia addr.IA, session sig_mgmt.SessionType, id sig_mgmt.MsgIdType) RegPollKey {
	if useID {
		return RegPollKey(fmt.Sprintf("%s-%s-%d", ia, session, id))
	} else {
		return RegPollKey(fmt.Sprintf("%s-%s", ia, session))
	}
}
