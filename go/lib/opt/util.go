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
	"crypto/sha256"

	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
)

func (e *Extn) DataHashed(payload common.RawBytes) common.RawBytes {
	shaChecksum := sha256.New()
	return shaChecksum.Sum(payload)[:16]
}

func (e *Extn) InitializePVF(key common.RawBytes, payload common.RawBytes) (common.RawBytes, *common.Error) {
	dataHash := e.DataHashed(payload)
	mac, err := util.InitMac(key)
	if err != nil {
		return nil, err
	}
	updatedPVF, err := util.Mac(mac, dataHash)
	if err != nil {
		return nil, err
	}
	e.PVF = updatedPVF
	return updatedPVF, nil
}

// return an updated PVF
func (e *Extn) UpdatePVF(key common.RawBytes) (common.RawBytes, *common.Error) {
	mac, err := util.InitMac(key)
	if err != nil {
		return nil, err
	}
	extendedPVF := append(e.DataHash, e.PVF...)
	updatedPVF, err := util.Mac(mac, extendedPVF)
	if err != nil {
		return nil, err
	}
	e.PVF = updatedPVF
	return updatedPVF, nil
}

// check the OV is valid for the current hop
func (e *Extn) ValidateOV(key common.RawBytes) (bool, *common.Error) {
	mac, err := util.InitMac(key)
	if err != nil {
		return false, err
	}
	meta := e.Meta
	index := int(byte(meta[0]) & byte(0x3f)) // mask out top 2 bits
	if index >= len(e.OVs) {
		return false, common.NewError(fmt.Sprintf("Invalid OV meta index: index %x, meta: %x", index, meta))
	}
	currentOV := e.OVs[index] // check with correct OV for the current hop
	computedOV, err := util.Mac(mac, e.DataHash)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(computedOV, currentOV) {
		return false, common.NewError(
			fmt.Sprintf("Invalid OV: expected OV %x got OV %x at index %x", computedOV, currentOV, index))
	}
	return true, nil
}

// check the OPV is valid for the current hop
func (e *Extn) ValidateOPV(key common.RawBytes, prevHopISD_AS int) (bool, *common.Error) {
	mac, err := util.InitMac(key)
	if err != nil {
		return false, err
	}
	meta := e.Meta
	index := int(byte(meta[0]) & byte(0x3f)) // mask out top 2 bits
	if index >= len(e.OVs) {
		return false, common.NewError(fmt.Sprintf("Invalid OPV meta index: index %x, meta: %x", index, meta))
	}

	currentOPV := e.OVs[index] // check with correct OPV for the current hop
	dataLength := len(e.PVF) + len(e.DataHash) + 4 + len(e.Timestamp)
	data := make(common.RawBytes, 0, dataLength)
	data = append(data, e.PVF...)
	data = append(data, e.DataHash...)
	prevHop := make([]byte, 4)
	binary.BigEndian.PutUint32(prevHop, uint32(prevHopISD_AS))
	data = append(data, prevHop...)
	data = append(data, e.Timestamp...)
	computedOPV, err := util.Mac(mac, data)
	computedOPV = computedOPV[:16]
	if err != nil {
		return false, err
	}
	if !bytes.Equal(computedOPV, currentOPV) {
		return false, common.NewError(
			fmt.Sprintf("Invalid OPV: expected OPV %v got OPV %v at index %v, data: %v, datalen: %v, prevHopISD_AS: %v", computedOPV, currentOPV, index, data, dataLength, prevHopISD_AS))
	}

	return true, nil
}

// return an updated Meta with incremented index
func (e *Extn) UpdateMeta() (common.RawBytes, *common.Error) {
	meta := e.Meta
	mode := byte(meta[0]) & byte(0xc0)       // mask out lower 6 bits
	index := int(byte(meta[0]) & byte(0x3f)) // mask out top 2 bits
	index += 1
	if index >= 0x3f { // value 0x3f is reserved for future use, larger values overflow
		return nil, common.NewError("Invalid OV, overflowed meta index", "index", index)
	}
	return common.RawBytes{mode | byte(index)}, nil
}
