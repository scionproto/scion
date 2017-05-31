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

const (
	preambleLength = 8
	DataHashLength = 16
	SessionIdLength = 16
	PVFLength = 16
)

func ExtnFromRaw(b common.RawBytes) (*Extn, *common.Error) {
	e := &Extn{}
	copy(e.DataHash, b[preambleLength:preambleLength+DataHashLength])
	dataHashOffset := preambleLength+DataHashLength
	copy(e.SessionId, b[dataHashOffset:SessionIdLength])
	sessionOffset := dataHashOffset + SessionIdLength
	copy(e.PVF, b[sessionOffset:PVFLength])
	return e, nil
}

func (e *Extn) Len() int {
	return len(e.SessionId) + len(e.PVF)
}

func (e *Extn) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (e *Extn) Type() common.ExtnType {
	return common.ExtnOPTType
}

func (e *Extn) String() string {
	return fmt.Sprintf("OPT Ext(%dB): DataHash: %v, Session: %v, PVF: %v", e.Len(), e.DataHash, e.SessionId, e.PVF)
}


func (e *Extn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, e.Len())
	if err := e.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *Extn) Write(b common.RawBytes) *common.Error {
	preambleLen := 8
	dataHashOffset := preambleLen + len(e.DataHash)
	sessionOffset := dataHashOffset + len(e.SessionId)
	pvfOffset := sessionOffset + len(e.PVF)
	copy(b[preambleLen:dataHashOffset], e.DataHash)
	copy(b[dataHashOffset:sessionOffset], e.SessionId)
	copy(b[sessionOffset:pvfOffset], e.PVF)
	return nil
}

func (e *Extn) Copy() common.Extension {
	return &Extn{DataHash: e.DataHash, SessionId: e.SessionId, PVF: e.PVF}
}

func (e *Extn) Reverse() (bool, *common.Error) {
	return false, nil
}
