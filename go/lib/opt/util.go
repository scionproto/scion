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
	"fmt"
	//"crypto/sha256"

	"github.com/netsec-ethz/scion/go/lib/opt"
	"github.com/netsec-ethz/scion/go/border/rpkt"
)

func (e *Extn) DataHashed(packet rpkt.RtrPkt) []byte {
	return nil
}

func (e *Extn) InitializePVF(sessionKey []byte) {
	dataHash := e.DataHashed(nil)
        e.PVF = cbcMACDummy(sessionKey, dataHash)
	return nil
}

func (e *Extn) UpdatePVF() {
	e.PVF = cbcMACDummy(e.SessionId, e.PVF)
	return nil
}

func cbcMACDummy(session []byte, PVF []byte) []byte {
	return nil
}