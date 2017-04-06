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

package l4

import (
	"bytes"
	"fmt"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/libscion"
)

const ErrorInvalidChksum = "Invalid L4 checksum"

type L4Header interface {
	fmt.Stringer
	L4Type() common.L4ProtocolType
	L4Len() int
	SetPldLen(int)
	GetCSum() common.RawBytes
	SetCSum(common.RawBytes)
	Copy() L4Header
	Write(common.RawBytes) *common.Error
	Pack(csum bool) (common.RawBytes, *common.Error)
	Validate(plen int) *common.Error
	Reverse()
}

func CalcCSum(h L4Header, addr, pld common.RawBytes) (common.RawBytes, *common.Error) {
	rawh, err := h.Pack(true)
	if err != nil {
		return nil, err
	}
	sum := libscion.Checksum(addr, []uint8{uint8(h.L4Type())}, rawh, pld)
	out := make(common.RawBytes, 2)
	common.Order.PutUint16(out, sum)
	return out, nil
}

func SetCSum(h L4Header, addr, pld common.RawBytes) *common.Error {
	out, err := CalcCSum(h, addr, pld)
	if err != nil {
		return err
	}
	h.SetCSum(out)
	return nil
}

func CheckCSum(h L4Header, addr, pld common.RawBytes) *common.Error {
	calc, err := CalcCSum(h, addr, pld)
	if err != nil {
		return err
	}
	exp := h.GetCSum()
	if bytes.Compare(exp, calc) != 0 {
		return common.NewError(ErrorInvalidChksum,
			"expected", exp, "actual", calc, "proto", h.L4Type())
	}
	return nil
}
