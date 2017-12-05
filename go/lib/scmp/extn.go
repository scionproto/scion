// Copyright 2016 ETH Zurich
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

package scmp

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

var _ common.Extension = (*Extn)(nil)

const (
	ExtnErrorFlag = 0x1
	ExtnHBHFlag   = 0x2
)

type Extn struct {
	Error    bool
	HopByHop bool
}

func ExtnFromRaw(b common.RawBytes) (*Extn, error) {
	e := &Extn{}
	flags := b[0]
	e.Error = (flags & ExtnErrorFlag) != 0
	e.HopByHop = (flags & ExtnHBHFlag) != 0
	return e, nil
}

func (e *Extn) Copy() common.Extension {
	return &Extn{Error: e.Error, HopByHop: e.HopByHop}
}

func (e *Extn) Write(b common.RawBytes) error {
	var flags uint8
	if e.Error {
		flags |= ExtnErrorFlag
	}
	if e.HopByHop {
		flags |= ExtnHBHFlag
	}
	b[0] = flags
	// Zero rest of first line
	copy(b[1:], make(common.RawBytes, common.ExtnFirstLineLen-1))
	return nil
}

func (e *Extn) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, e.Len())
	if err := e.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *Extn) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (e *Extn) Len() int {
	return common.ExtnFirstLineLen
}

func (e *Extn) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (e *Extn) Type() common.ExtnType {
	return common.ExtnSCMPType
}

func (e *Extn) String() string {
	return fmt.Sprintf("SCMP Ext(%dB): Error? %v HopByHop: %v", e.Len(), e.Error, e.HopByHop)
}
