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

package spkt

import (
	"github.com/scionproto/scion/go/lib/common"
)

var _ common.Extension = (*OneHopPath)(nil)

type OneHopPath struct{}

const OneHopPathLen = common.ExtnFirstLineLen

func (o OneHopPath) Write(b common.RawBytes) error {
	copy(b, make(common.RawBytes, OneHopPathLen))
	return nil
}

func (o OneHopPath) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o OneHopPath) Copy() common.Extension {
	return &OneHopPath{}
}

func (o OneHopPath) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (o OneHopPath) Len() int {
	return OneHopPathLen
}

func (o OneHopPath) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (o OneHopPath) Type() common.ExtnType {
	return common.ExtnOneHopPathType
}

func (o *OneHopPath) String() string {
	return "OneHopPath"
}
