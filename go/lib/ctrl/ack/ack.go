// Copyright 2018 Anapaya Systems
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

package ack

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Ack)(nil)

type Ack struct {
	Err     proto.Ack_ErrCode
	ErrDesc string
}

func NewFromRaw(b common.RawBytes) (*Ack, error) {
	a := &Ack{}
	return a, proto.ParseFromRaw(a, a.ProtoId(), b)
}

func (a *Ack) ProtoId() proto.ProtoIdType {
	return proto.Ack_TypeID
}

func (a *Ack) Write(b common.RawBytes) (int, error) {
	return proto.WriteRoot(a, b)
}

func (a *Ack) String() string {
	if a.Err == proto.Ack_ErrCode_ok {
		return "ACK ok"
	}
	return fmt.Sprintf("ACK %s: %s", a.Err, a.ErrDesc)
}
