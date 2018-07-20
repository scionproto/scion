// Copyright 2018 ETH Zurich
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

package drkey

import (
	"crypto/sha256"

	"github.com/scionproto/scion/go/lib/addr"

	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	drkeySalt   = "Derive DRKey Key" // same as in Python
	drkeyLength = 16
)

// DeriveDRKeySV derives a DRKey secret value based on a master secret.
func DeriveDRKeySV(masterSecret, date common.RawBytes, expTime uint32) *DRKeySV {
	msLen := len(masterSecret)
	all := make(common.RawBytes, msLen+len(date))
	masterSecret.WritePld(all[:msLen])
	date.WritePld(all[msLen:])
	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	return &DRKeySV{Key: key[:drkeyLength], ExpTime: expTime}
}

// DeriveDRKeyLvl1 derives a first level DRKey based on a per-AS secret value.
func DeriveDRKeyLvl1(sv *DRKeySV, srcIa, dstIa addr.IA, expTime uint32) (*DRKeyLvl1, error) {
	h, err := util.InitMac(sv.Key)
	if err != nil {
		return nil, err
	}
	all := make(common.RawBytes, addr.IABytes)
	dstIa.Write(all)
	key, err := util.Mac(h, all)
	if err != nil {
		return nil, err
	}
	return &DRKeyLvl1{SrcIa: srcIa, DstIa: dstIa, ExpTime: expTime, Key: key[:drkeyLength]}, nil
}

// DeriveDRKeyLvl2 derives a second level DRKey based on a first level key.
func DeriveDRKeyLvl2(in *DRKeyLvl1, out *DRKeyLvl2) error {
	h, err := util.InitMac(in.Key)
	if err != nil {
		return err
	}
	p := []byte(out.Proto)
	pLen := len(p)
	inputLen := 1 + pLen
	switch out.Type {
	case AS2Host:
		it, err := InputTypeFromHostTypes(out.DstHost.Type(), addr.HostTypeNone)
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	case Host2Host:
		it, err := InputTypeFromHostTypes(out.SrcHost.Type(), out.DstHost.Type())
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	case AS2HostPair:
		it, err := InputTypeFromHostTypes(out.DstHost.Type(), out.AddHost.Type())
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	default:
		return common.NewBasicError("Unknown DRKey type", nil)
	}
	all := make(common.RawBytes, inputLen)
	copy(all[:1], common.RawBytes{uint8(pLen)})
	copy(all[1:], p)
	switch out.Type {
	case AS2Host:
		copy(all[pLen+1:], out.DstHost.Pack())
	case Host2Host:
		copy(all[pLen+1:], out.SrcHost.Pack())
		copy(all[pLen+1+out.SrcHost.Size():], out.DstHost.Pack())
	case AS2HostPair:
		copy(all[pLen+1:], out.DstHost.Pack())
		copy(all[pLen+1+out.DstHost.Size():], out.AddHost.Pack())
	default:
		return common.NewBasicError("Unknown DRKey type", nil)
	}
	key, err := util.Mac(h, all)
	if err != nil {
		return err
	}
	out.Key = key
	return nil
}

// func EncryptDRKeyLvl1(drkey DRKeyLvl1) common.RawBytes {
// 	return nil
// }

// func DecryptDRKeyLvl1(common.RawBytes) DRKeyLvl1 {

// }
