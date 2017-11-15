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

package siginfo

import (
	"fmt"
	"math"
	"sync"
	"time"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

const (
	maxFail        uint16 = math.MaxUint16
	failExpiration        = 5 * time.Minute
)

type SigIdType string

type SigMap sync.Map

func (sm *SigMap) Delete(key SigIdType) {
	(*sync.Map)(sm).Delete(key)
}

func (sm *SigMap) Load(key SigIdType) (*Sig, bool) {
	value, ok := (*sync.Map)(sm).Load(key)
	if value == nil {
		return nil, ok
	}
	return value.(*Sig), ok
}

func (sm *SigMap) LoadOrStore(key SigIdType, value *Sig) (*Sig, bool) {
	actual, ok := (*sync.Map)(sm).LoadOrStore(key, value)
	if actual == nil {
		return nil, ok
	}
	return actual.(*Sig), ok
}

func (sm *SigMap) Store(key SigIdType, value *Sig) {
	(*sync.Map)(sm).Store(key, value)
}

func (sm *SigMap) Range(f func(key SigIdType, value *Sig) bool) {
	(*sync.Map)(sm).Range(func(key, value interface{}) bool {
		return f(key.(SigIdType), value.(*Sig))
	})
}

// return the Sig with the lowest fail count.
func (sm *SigMap) GetSig(currSigId SigIdType) *Sig {
	var s *Sig
	var minFail uint16 = math.MaxUint16
	sm.Range(func(id SigIdType, sig *Sig) bool {
		if id == currSigId {
			// If a current Sig ID is supplied, don't reply with the same one.
			return true
		}
		failCount := sig.FailCount()
		if failCount < minFail {
			s = sig
			minFail = failCount
		}
		return true
	})
	return s
}

type Sig struct {
	IA          *addr.ISD_AS
	Id          SigIdType
	Host        addr.HostAddr
	CtrlL4Port  int
	EncapL4Port int
	Active      bool
	// If from local config file true, else from discovery, so false.
	Static         bool
	statsMutex     sync.RWMutex
	statsUpdate    time.Time
	statsFailCount uint16
}

func NewSig(ia *addr.ISD_AS, id SigIdType, host addr.HostAddr,
	ctrlPort, encapPort int, static bool) *Sig {
	return &Sig{
		IA: ia, Id: id, Host: host, CtrlL4Port: ctrlPort,
		EncapL4Port: encapPort, Active: true, Static: static, statsUpdate: time.Now(),
	}
}

func (s *Sig) CtrlSnetAddr() *snet.Addr {
	return &snet.Addr{IA: s.IA, Host: s.Host, L4Port: uint16(s.CtrlL4Port)}
}

func (s *Sig) EncapSnetAddr() *snet.Addr {
	return &snet.Addr{IA: s.IA, Host: s.Host, L4Port: uint16(s.EncapL4Port)}
}

func (s *Sig) FailCount() uint16 {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()
	return s.statsFailCount
}

func (s *Sig) Fail() {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()
	s.statsUpdate = time.Now()
	if s.statsFailCount < maxFail {
		s.statsFailCount += 1
	}
}

func (s *Sig) ExpireFails() {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()
	if time.Since(s.statsUpdate) > failExpiration {
		s.statsFailCount /= 2
	}
}

func (s *Sig) Cleanup() error {
	// Nothing to do, currently.
	return nil
}

func (s *Sig) String() string {
	return fmt.Sprintf("%s,[%s]:%d:%d", s.IA, s.Host, s.CtrlL4Port, s.EncapL4Port)
}
