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

const (
	ExtnHBHFlag   = 0x2
)

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
	//HopByHop bool
	Flags     [8]common.RawBytes
	DataHash  [16]common.RawBytes
	SessionId [16]common.RawBytes
	PVF       [16]common.RawBytes
}

func ExtnFromRaw(b common.RawBytes) (*Extn, *common.Error) {
	e := &Extn{}
	//flags := b[0]
	/*e.Flags = b[0:8] //(flags & ExtnHBHFlag) != 0 // mask out the HopByHop flag and check if set
	e.DataHash = b[8:24]
	e.SessionId = b[24:40]
	e.PVF = b[40:56]*/
	return e, nil
}

func (e *Extn) Len() int {
	return 0  // common.ExtnFirstLineLen + len(e.SessionId) + len(e.PVF)
}

func (e *Extn) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (e *Extn) Type() common.ExtnType {
	return common.ExtnOPTType
}

func (e *Extn) String() string {
	return fmt.Sprintf("OPT Ext(%dB): Flags? %v PVF: %v", e.Len(), e.Flags, e.PVF)
}


func (e *Extn) Pack() (common.RawBytes, *common.Error) {
	b := make(common.RawBytes, e.Len())
	if err := e.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *Extn) Write(b common.RawBytes) *common.Error {
	/* var flags uint8
	if (e.Flags) {
		flags |= ExtnHBHFlag // set HopByHop flag
	}
	b[0] = flags */
	// Pad rest of first line
	//copy(b[1:8], make(common.RawBytes, common.ExtnFirstLineLen-1))
	/*copy(b[0:8], make(common.RawBytes, common.ExtnFirstLineLen))
	b[8:24] = e.DataHash
	b[24:40] = e.SessionId
	b[40:56] = e.PVF*/
	return nil
}

func (e *Extn) Copy() common.Extension {
	return &Extn{Flags: e.Flags, DataHash: e.DataHash, SessionId: e.SessionId, PVF: e.PVF}
}

func (e *Extn) Reverse() (bool, *common.Error) {
	return false, nil
}
