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

package drkey

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// SpecificDeriver implements the specific drkey derivation.
type SpecificDeriver struct {
	buf [32]byte
}

// DeriveLvl1 returns the Lvl1 derived key.
func (p *SpecificDeriver) DeriveLvl1(dstIA addr.IA, key Key) (Key, error) {
	len := inputDeriveLvl1(p.buf[:], dstIA)
	outKey, err := deriveKey(p.buf[:len], key)
	return outKey, err
}

func inputDeriveLvl1(buf []byte, dstIA addr.IA) int {
	_ = buf[aes.BlockSize-1]
	buf[0] = byte(asToAs)
	binary.BigEndian.PutUint64(buf[1:], uint64(dstIA))
	copy(buf[9:], zeroBlock[:])

	return aes.BlockSize
}

func (p *SpecificDeriver) inputDeriveLvl2(input []byte, derType keyType,
	host hostAddr) int {
	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	input[1] = uint8(host.AddrType&0x3)<<2 | uint8(host.AddrLen&0x3)
	copy(input[2:], hostAddr)
	copy(input[2+l:inputLength], zeroBlock[:])

	return inputLength
}

// DeriveASHost returns the ASHost derived key.
func (p *SpecificDeriver) DeriveASHost(dstHost string, key Key) (Key, error) {
	host, err := packtoHostAddr(dstHost)
	if err != nil {
		return Key{}, serrors.WrapStr("parsing dst host", err)
	}
	len := p.inputDeriveLvl2(p.buf[:], asToHost, host)
	outKey, err := deriveKey(p.buf[:len], key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (p *SpecificDeriver) DeriveHostAS(srcHost string, key Key) (Key, error) {
	host, err := packtoHostAddr(srcHost)
	if err != nil {
		return Key{}, serrors.WrapStr("parsing src host", err)
	}
	len := p.inputDeriveLvl2(p.buf[:], hostToAS, host)
	outKey, err := deriveKey(p.buf[:len], key)
	return outKey, err
}

// DeriveHostToHost returns the HostHost derived key.
func (p *SpecificDeriver) DeriveHostToHost(dstHost string, key Key) (Key, error) {
	host, err := packtoHostAddr(dstHost)
	if err != nil {
		return Key{}, serrors.WrapStr("deriving input H2H", err)
	}
	len := inputDeriveHostToHost(p.buf[:], host)
	outKey, err := deriveKey(p.buf[:len], key)
	return outKey, err
}
