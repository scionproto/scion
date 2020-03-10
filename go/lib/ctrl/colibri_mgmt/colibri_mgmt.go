// Copyright 2020 ETH Zurich, Anapaya Systems
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

package colibri_mgmt

import (
	"strings"

	"github.com/scionproto/scion/go/proto"
)

type ColibriRequestPayload struct {
	Which    proto.ColibriRequestPayload_Which
	Request  *Request
	Response *Response
}

var _ proto.Cerealizable = (*ColibriRequestPayload)(nil)

func (p *ColibriRequestPayload) ProtoId() proto.ProtoIdType {
	return proto.ColibriRequestPayload_TypeID
}

func (p *ColibriRequestPayload) String() string {
	strs := make([]string, 1, 2)
	strs[0] = "ColibriRequestPayload:"
	switch p.Which {
	case proto.ColibriRequestPayload_Which_request:
		strs = append(strs, "Request")
	case proto.ColibriRequestPayload_Which_response:
		strs = append(strs, "Response")
	default:
		strs = append(strs, "Unknown subtype")
	}
	return strings.Join(strs, " ")
}

func (p *ColibriRequestPayload) PackRoot() ([]byte, error) {
	return proto.PackRoot(p)
}

func NewFromRaw(b []byte) (*ColibriRequestPayload, error) {
	pld := &ColibriRequestPayload{}
	err := proto.ParseFromRaw(pld, b)
	if err != nil {
		return nil, err
	}
	return pld, nil
}
