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

	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/util"
	"bytes"
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
		return false, common.NewError("Invalid OV meta index", "index", index, "meta", meta, "sessionID", e.SessionId)
	}
	currentOV := e.OVs[index] // check with correct OV for the current hop
	computedOV, err := util.Mac(mac, e.DataHash)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(computedOV, currentOV) {
		return false, common.NewError("Invalid OV", "expected OV", computedOV, "got OV", currentOV, "at index", index, "from meta", meta)
	}
	return true, nil
}

// return an updated Meta index
func (e *Extn) UpdateMeta(meta common.RawBytes) (common.RawBytes, *common.Error) {
	mode := byte(meta[0]) & byte(0xc) // mask out lower 6 bits
	index := int(byte(meta[0]) & byte(0x3f)) // mask out top 2 bits
	index += 1
	if index >= 0x3f { // value 0x3f is reserved for future use, larger values overflow
		return nil, common.NewError("Invalid OV, overflowed meta index", "index", index)
	}
	return common.RawBytes{mode | byte(index)}, nil
}
