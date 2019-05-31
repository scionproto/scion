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

package layers

import "github.com/scionproto/scion/go/lib/common"

var _ common.Extension = (*ExtnE2EDebug)(nil)

type ExtnE2EDebug struct {
	ID [5]byte
}

const E2EDebugLen = common.ExtnFirstLineLen

func NewExtnE2EDebugFromLayer(extension *Extension) (*ExtnE2EDebug, error) {
	var extn ExtnE2EDebug
	if err := extn.DecodeFromLayer(extension); err != nil {
		return nil, err
	}
	return &extn, nil
}

func (o *ExtnE2EDebug) DecodeFromLayer(extension *Extension) error {
	if len(extension.Data) != common.LineLen-3 {
		return common.NewBasicError("bad length for E2E debug extension", nil,
			"actual", len(extension.Data), "want", common.LineLen-3)
	}
	copy(o.ID[:], extension.Data)
	return nil
}

func (o ExtnE2EDebug) Write(b common.RawBytes) error {
	copy(b[:5], o.ID[:])
	return nil
}

func (o ExtnE2EDebug) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o ExtnE2EDebug) Copy() common.Extension {
	return &ExtnE2EDebug{}
}

func (o ExtnE2EDebug) Reverse() (bool, error) {
	return true, nil
}

func (o ExtnE2EDebug) Len() int {
	return E2EDebugLen
}

func (o ExtnE2EDebug) Class() common.L4ProtocolType {
	return common.End2EndClass
}

func (o ExtnE2EDebug) Type() common.ExtnType {
	return common.ExtnE2EDebugType
}

func (o ExtnE2EDebug) String() string {
	return "E2EDebug"
}
