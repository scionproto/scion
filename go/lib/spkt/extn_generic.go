// Copyright 2019 ETH Zurich
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

var _ common.Extension = (*UnknownExtension)(nil)

type UnknownExtension struct {
	// Length, in bytes, including 3-byte extension header
	Length    int
	TypeField uint8
}

func (o UnknownExtension) Write(b common.RawBytes) error {
	for i := 0; i < o.Length; i++ {
		b[i] = 0
	}
	return nil
}

func (o UnknownExtension) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o UnknownExtension) Copy() common.Extension {
	return &UnknownExtension{Length: o.Length}
}

func (o UnknownExtension) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (o UnknownExtension) Len() int {
	return o.Length
}

func (o UnknownExtension) Class() common.L4ProtocolType {
	return common.L4None
}

func (o UnknownExtension) Type() common.ExtnType {
	return common.ExtnType{Type: o.TypeField}
}

func (o UnknownExtension) String() string {
	return "Unknown"
}
