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

package proto

import (
	"github.com/netsec-ethz/scion/go/lib/util"
)

const (
	ErrorPathSegASMs    = "Unable to get AS Markings from PathSegment"
	ErrorPathSegASMIdx  = "Invalid AS Marking index"
	ErrorPathSegPCBMs   = "Unable to get PCB Markings from AS Marking"
	ErrorPathSegPCBMIdx = "Invalid PCB Marking index"
	ErrorPathSegHopF    = "Unable to get Hop Field from PCB Marking"
)

func (s PCBMarking) HopF() (util.RawBytes, *util.Error) {
	rawH, err := s.Hof()
	if err != nil {
		return nil, util.NewError(ErrorPathSegHopF, "err", err)
	}
	return rawH, nil
}

func (s ASMarking) PCBM(idx int) (*PCBMarking, *util.Error) {
	pcbms, err := s.Pcbms()
	if err != nil {
		return nil, util.NewError(ErrorPathSegPCBMs, "err", err)
	}
	maxIdx := pcbms.Len() - 1
	if idx < -1 || idx > maxIdx {
		return nil, util.NewError(ErrorPathSegASMIdx, "max", maxIdx, "actual", idx)
	}
	if idx == -1 {
		idx = maxIdx
	}
	pcbm := pcbms.At(idx)
	return &pcbm, nil
}

func (s PathSegment) ASM(idx int) (*ASMarking, *util.Error) {
	asms, err := s.Asms()
	if err != nil {
		return nil, util.NewError(ErrorPathSegASMs, "err", err)
	}
	maxIdx := asms.Len() - 1
	if idx < -1 || idx > maxIdx {
		return nil, util.NewError(ErrorPathSegASMIdx, "max", maxIdx, "actual", idx)
	}
	if idx == -1 {
		idx = maxIdx
	}
	asm := asms.At(idx)
	return &asm, nil
}

func (s PathSegment) LastHopF() (util.RawBytes, *util.Error) {
	asm, err := s.ASM(-1)
	if err != nil {
		return nil, err
	}
	pcbm, err := asm.PCBM(0)
	if err != nil {
		return nil, err
	}
	rawH, err := pcbm.HopF()
	if err != nil {
		return nil, err
	}
	return rawH, nil
}
