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
	"github.com/scionproto/scion/go/lib/scrypto"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	drkeySalt   = "Derive DRKey Key" // same as in Python
	drkeyLength = 16
)

func (sv *DRKeySV) SetKey(secret, date common.RawBytes) error {
	msLen := len(secret)
	all := make(common.RawBytes, msLen+len(date))
	secret.WritePld(all[:msLen])
	date.WritePld(all[msLen:])
	key := pbkdf2.Key(all, []byte(drkeySalt), 1000, 16, sha256.New)
	sv.Key = key
	return nil
}

func (k *DRKeyLvl1) SetKey(secret common.RawBytes) error {
	h, err := scrypto.InitMac(secret)
	if err != nil {
		return err
	}
	all := make(common.RawBytes, addr.IABytes)
	k.DstIa.Write(all)
	key, err := scrypto.Mac(h, all)
	if err != nil {
		return err
	}
	k.Key = key
	return nil
}

func (k *DRKeyLvl2) SetKey(secret common.RawBytes) error {
	h, err := scrypto.InitMac(secret)
	if err != nil {
		return err
	}
	p := []byte(k.Proto)
	pLen := len(p)
	inputLen := 1 + pLen
	switch k.Type {
	case AS2Host:
		it, err := InputTypeFromHostTypes(k.DstHost.Type(), addr.HostTypeNone)
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	case Host2Host:
		it, err := InputTypeFromHostTypes(k.SrcHost.Type(), k.DstHost.Type())
		if err != nil {
			return err
		}
		inputLen += it.RequiredLength()
	case AS2HostPair:
		it, err := InputTypeFromHostTypes(k.DstHost.Type(), k.AddHost.Type())
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
	switch k.Type {
	case AS2Host:
		copy(all[pLen+1:], k.DstHost.Pack())
	case Host2Host:
		copy(all[pLen+1:], k.SrcHost.Pack())
		copy(all[pLen+1+k.SrcHost.Size():], k.DstHost.Pack())
	case AS2HostPair:
		copy(all[pLen+1:], k.DstHost.Pack())
		copy(all[pLen+1+k.DstHost.Size():], k.AddHost.Pack())
	default:
		return common.NewBasicError("Unknown DRKey type", nil)
	}
	key, err := scrypto.Mac(h, all)
	if err != nil {
		return err
	}
	k.Key = key
	return nil
}

func EncryptDRKeyLvl1(drkey *DRKeyLvl1, nonce, pubkey,
	privkey common.RawBytes) (common.RawBytes, error) {
	keyLen := len(drkey.Key)
	msg := make(common.RawBytes, addr.IABytes+keyLen)
	drkey.SrcIa.Write(msg)
	drkey.Key.WritePld(msg[addr.IABytes:])
	cipher, err := scrypto.Encrypt(msg, nonce, pubkey, privkey, "Curve25519xSalsa20Poly1305")
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

func DecryptDRKeyLvl1(cipher, nonce, pubkey, privkey common.RawBytes) (*DRKeyLvl1, error) {
	msg, err := scrypto.Decrypt(cipher, nonce, pubkey, privkey, "Curve25519xSalsa20Poly1305")
	if err != nil {
		return nil, err
	}
	srcIa := addr.IAFromRaw(msg[:addr.IABytes])
	key := msg[addr.IABytes:]
	return &DRKeyLvl1{SrcIa: srcIa, Key: key}, nil
}
