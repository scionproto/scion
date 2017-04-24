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

package opt

import (
	//"github.com/netsec-ethz/scion/go/border/rpkt"
	//"github.com/netsec-ethz/scion/go/lib/util"
	//"crypto/sha256"
)

//func (e *Extn) DataHashed(packet rpkt.RtrPkt) []byte {
func (e *Extn) DataHashed(packet interface{}) []byte {
	//shaChecksum := sha256.New
	//return shaChecksum(packet)
	return make([]byte, 42)
}

func (e *Extn) InitializePVF(sessionKey []byte, payload []byte) {
	dataHash := e.DataHashed(payload)
        //e.PVF = cbcMAC(sessionKey, dataHash)
        _ = cbcMAC(sessionKey, dataHash)
}

//func (e *Extn) UpdatePVF(packet *rpkt.RtrPkt) {
func (e *Extn) UpdatePVF(packet *interface{}) {
	/*localSecret, _ := packet.CalcDRKey()
	// K_{AS_i}^session = PRF_{AS_i -> S, D}(SessionId)
	sessionKey := cbcMAC(localSecret, e.SessionId)
	e.PVF = cbcMAC(sessionKey, e.PVF)*/
}

func cbcMAC(session []byte, PVF []byte) []byte {
	//mac, _ := util.CBCMac(session, PVF)
	return make([]byte, 42)
}