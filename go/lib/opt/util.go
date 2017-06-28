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
	"github.com/netsec-ethz/scion/go/lib/common"
)

//func (e *Extn) DataHashed(packet rpkt.RtrPkt) []byte {
func (e *Extn) DataHashed(packet Extn) []byte {
	/*shaChecksum := sha256.New
	return shaChecksum(packet)*/
	return make(common.RawBytes, 16)
}

/*func (e *Extn) InitializePVF(sessionKey []byte, payload []byte) {
	dataHash := e.DataHashed(payload)
        e.PVF = cbcMAC(sessionKey, dataHash)
}*/

// return an updated PVF
func (e *Extn) UpdatePVF() common.RawBytes {
	/*localSecret, _ := packet.CalcDRKey()
	// K_{AS_i}^session = PRF_{AS_i -> S, D}(SessionId)
	sessionKey := cbcMAC(localSecret, e.SessionId)
	e.PVF = cbcMAC(sessionKey, e.PVF)
	PVF := e.PVF*/
	// WIP
	return make(common.RawBytes, 16)
}

func cbcMAC(session []byte, PVF []byte) []byte {
	/*mac, _ := util.CBCMac(session, PVF)
	return mac*/
	// WIP
	return make(common.RawBytes, 16)
}
