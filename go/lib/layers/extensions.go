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

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
)

func ExtensionFactory(class common.L4ProtocolType, extension *Extension) (common.Extension, error) {
	switch class {
	case common.HopByHopClass:
		switch extension.Type {
		case common.ExtnSCMPType.Type:
			return NewExtnSCMPFromLayer(extension)
		case common.ExtnOneHopPathType.Type:
			return NewExtnOHPFromLayer(extension)
		default:
			return NewExtnUnknownFromLayer(common.HopByHopClass, extension)
		}
	case common.End2EndClass:
		switch extension.Type {
		default:
			return NewExtnUnknownFromLayer(common.End2EndClass, extension)
		}
	default:
		return nil, common.NewBasicError("unknown extension class", nil, "class", class)
	}
}

var _ common.Extension = (*ExtnOHP)(nil)

type ExtnOHP struct{}

const OneHopPathLen = common.ExtnFirstLineLen

func NewExtnOHPFromLayer(extension *Extension) (*ExtnOHP, error) {
	var extn ExtnOHP
	if err := extn.DecodeFromLayer(extension); err != nil {
		return nil, err
	}
	return &extn, nil
}

func (o *ExtnOHP) DecodeFromLayer(extension *Extension) error {
	if len(extension.Data) != common.LineLen-3 {
		return common.NewBasicError("bad length for OHP extension", nil,
			"actual", len(extension.Data), "want", common.LineLen-3)
	}
	return nil
}

func (o ExtnOHP) Write(b common.RawBytes) error {
	for i := 0; i < OneHopPathLen; i++ {
		b[i] = 0
	}
	return nil
}

func (o ExtnOHP) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, o.Len())
	if err := o.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (o ExtnOHP) Copy() common.Extension {
	return &ExtnOHP{}
}

func (o ExtnOHP) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (o ExtnOHP) Len() int {
	return OneHopPathLen
}

func (o ExtnOHP) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (o ExtnOHP) Type() common.ExtnType {
	return common.ExtnOneHopPathType
}

func (o ExtnOHP) String() string {
	return "OneHopPath"
}

const (
	ExtnSCMPErrorFlag = 0x01
	ExtnSCMPHBHFlag   = 0x02
)

var _ common.Extension = (*ExtnSCMP)(nil)

type ExtnSCMP struct {
	Error    bool
	HopByHop bool
}

func NewExtnSCMPFromLayer(extension *Extension) (*ExtnSCMP, error) {
	var extn ExtnSCMP
	if err := extn.DecodeFromLayer(extension); err != nil {
		return nil, err
	}
	return &extn, nil
}

func (e *ExtnSCMP) DecodeFromLayer(extension *Extension) error {
	return e.DecodeFromBytes(extension.Data)
}

func (e *ExtnSCMP) DecodeFromBytes(b []byte) error {
	if len(b) < common.LineLen-3 {
		return common.NewBasicError("bad length for SCMP extension", nil,
			"actual", len(b), "want", common.LineLen-3)
	}
	flags := b[0]
	e.Error = (flags & ExtnSCMPErrorFlag) != 0
	e.HopByHop = (flags & ExtnSCMPHBHFlag) != 0
	return nil
}

func ExtnSCMPFromRaw(b common.RawBytes) (*ExtnSCMP, error) {
	e := &ExtnSCMP{}
	if err := e.DecodeFromBytes(b); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *ExtnSCMP) Copy() common.Extension {
	return &ExtnSCMP{Error: e.Error, HopByHop: e.HopByHop}
}

func (e *ExtnSCMP) Write(b common.RawBytes) error {
	var flags uint8
	if e.Error {
		flags |= ExtnSCMPErrorFlag
	}
	if e.HopByHop {
		flags |= ExtnSCMPHBHFlag
	}
	b[0] = flags
	// Zero rest of first line
	copy(b[1:], make(common.RawBytes, common.ExtnFirstLineLen-1))
	return nil
}

func (e *ExtnSCMP) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, e.Len())
	if err := e.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (e *ExtnSCMP) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (e *ExtnSCMP) Len() int {
	return common.ExtnFirstLineLen
}

func (e *ExtnSCMP) Class() common.L4ProtocolType {
	return common.HopByHopClass
}

func (e *ExtnSCMP) Type() common.ExtnType {
	return common.ExtnSCMPType
}

func (e *ExtnSCMP) String() string {
	return fmt.Sprintf("SCMP Ext(%dB): Error? %v HopByHop: %v", e.Len(), e.Error, e.HopByHop)
}

var _ common.Extension = (*ExtnUnknown)(nil)

// ExtnUnknown implements common.Extension for an unknown extension.
type ExtnUnknown struct {
	// ClassField is the Extension class. We include it here because we cannot
	// implement the Class() method of the interface otherwise.
	ClassField common.L4ProtocolType
	TypeField  uint8
	// Length, in bytes, not including the 3-byte extension header
	Length int
}

func NewExtnUnknownFromLayer(class common.L4ProtocolType,
	extension *Extension) (*ExtnUnknown, error) {

	var extn ExtnUnknown
	extn.ClassField = class
	if err := extn.DecodeFromLayer(extension); err != nil {
		return nil, err
	}
	return &extn, nil
}

func (u *ExtnUnknown) DecodeFromLayer(extension *Extension) error {
	if (len(extension.Data)+common.ExtnSubHdrLen)%common.LineLen != 0 {
		return common.NewBasicError("length of unknown extension not aligned", nil,
			"length", len(extension.Data))
	}
	u.Length = int(extension.NumLines)*common.LineLen - common.ExtnSubHdrLen
	u.TypeField = extension.Type
	return nil
}

func (u ExtnUnknown) Write(b common.RawBytes) error {
	for i := 0; i < u.Length; i++ {
		b[i] = 0
	}
	return nil
}

func (u ExtnUnknown) Pack() (common.RawBytes, error) {
	b := make(common.RawBytes, u.Len())
	if err := u.Write(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (u ExtnUnknown) Copy() common.Extension {
	return &ExtnUnknown{Length: u.Length}
}

func (u ExtnUnknown) Reverse() (bool, error) {
	// Reversing removes the extension.
	return false, nil
}

func (u ExtnUnknown) Len() int {
	return u.Length
}

func (u ExtnUnknown) Class() common.L4ProtocolType {
	return u.ClassField
}

func (u ExtnUnknown) Type() common.ExtnType {
	return common.ExtnType{Class: u.ClassField, Type: u.TypeField}
}

func (u ExtnUnknown) String() string {
	return "Unknown"
}

// ExtensionDataToExtensionLayer build a low level extension representation
// from a high level interface.
func ExtensionDataToExtensionLayer(nextHdr common.L4ProtocolType,
	data common.Extension) (*Extension, error) {

	bytes, err := data.Pack()
	if err != nil {
		return nil, err
	}
	return &Extension{
		NextHeader: nextHdr,
		Type:       data.Type().Type,
		Data:       bytes,
	}, nil
}
