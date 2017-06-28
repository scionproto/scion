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

	"github.com/netsec-ethz/scion/go/lib/common"
)

// satisfies the interface common.Extension in common/extn.go
var _ common.Extension = (*Extn)(nil)

/*
OPT extension Header

0B       1        2        3        4        5        6        7
+--------+--------+--------+--------+--------+--------+--------+--------+
| xxxxxxxxxxxxxxxxxxxxxxxx |                    padding                 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                               DataHash...                             |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                            ...DataHash                                |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                               Session ID...                           |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                            ...Session ID                              |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                                  PVF...                               |
+--------+--------+--------+--------+--------+--------+--------+--------+
|                               ...PVF                                  |
+--------+--------+--------+--------+--------+--------+--------+--------+
*/

type Extn struct { // fields of the extension
	DataHash  common.RawBytes
	SessionId common.RawBytes
	PVF       common.RawBytes
}

func (e *Extn) Len() int {
	return common.ExtnFirstLineLen + len(e.SessionId) + len(e.PVF)
}

func (e *Extn) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (e *Extn) Type() common.ExtnType {
	return common.ExtnOPTType
}

func (e *Extn) String() string {
	return fmt.Sprintf("OPT Ext(%dB): DataHash: %v SessionID: %v PVF: %v", e.Len(), e.DataHash, e.SessionId, e.PVF)
}

func (e *Extn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, e.Len())
	if err := e.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *Extn) Write(b common.RawBytes) *common.Error {
	if len(b) < e.Len() {
		return common.NewError("Buffer too short", "method", "SCIONOriginPathTraceExtn.Write",
			"expected min", e.Len(), "actual", len(b))
	}

	datahashOffset := PaddingLength
	sessionIDOffset := datahashOffset + DatahashLength
	PVFOffset := sessionIDOffset + SessionIDLength
	totalLength := sessionIDOffset + PVFOffset

	copy(b[datahashOffset:sessionIDOffset], e.DataHash)
	copy(b[sessionIDOffset:PVFOffset], e.SessionId)
	copy(b[PVFOffset:totalLength], e.PVF)
	return nil
}

// Set the Datahash.
func (e *Extn) SetDatahash(datahash common.RawBytes) *common.Error {
	if len(e.DataHash) != len(datahash) {
		return common.NewError("The length does not match",
			"expected", len(e.DataHash), "actual", len(datahash))
	}
	copy(e.DataHash, datahash)
	return nil
}

// Set the SessionID.
func (e *Extn) SetSessionID(sessionID common.RawBytes) *common.Error {
	if len(e.SessionId) != len(sessionID) {
		return common.NewError("The length does not match",
			"expected", len(e.SessionId), "actual", len(sessionID))
	}
	copy(e.SessionId, sessionID)
	return nil
}

// Set the PVF
func (e *Extn) SetPVF(pathVerificationField common.RawBytes) *common.Error {
	if len(e.PVF) != len(pathVerificationField) {
		return common.NewError("The length does not match",
			"expected", len(e.PVF), "actual", len(pathVerificationField))
	}
	copy(e.PVF, pathVerificationField)
	return nil
}

func (e *Extn) Copy() common.Extension {
	return &Extn{DataHash: e.DataHash, SessionId: e.SessionId, PVF: e.PVF}
}

func (e *Extn) Reverse() (bool, *common.Error) {
	// WIP
	return true, nil
}
