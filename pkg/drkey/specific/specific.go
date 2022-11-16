// Copyright 2022 ETH Zurich
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

package specific

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// SpecificDeriver implements the specific drkey derivation.
type Deriver struct{}

// DeriveLevel1 returns the Level1 derived key.
func (d Deriver) DeriveLevel1(
	dstIA addr.IA,
	key drkey.Key,
) (drkey.Key, error) {

	buf := make([]byte, aes.BlockSize)
	len := serializeLevel1Input(buf, dstIA)
	outKey, err := drkey.DeriveKey(buf[:len], key)
	return outKey, err
}

// DeriveASHost returns the ASHost derived key.
func (d Deriver) DeriveASHost(
	dstHost string,
	key drkey.Key,
) (drkey.Key, error) {

	host, err := drkey.HostAddrFromString(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("parsing dst host", err)
	}
	buf := make([]byte, 32)
	len := d.serializeLevel2Input(buf, drkey.AsHost, host)
	outKey, err := drkey.DeriveKey(buf[:len], key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (p Deriver) DeriveHostAS(srcHost string, key drkey.Key) (drkey.Key, error) {
	host, err := drkey.HostAddrFromString(srcHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("parsing src host", err)
	}
	buf := make([]byte, 32)
	len := p.serializeLevel2Input(buf, drkey.HostAS, host)
	outKey, err := drkey.DeriveKey(buf[:len], key)
	return outKey, err
}

// DeriveHostHost returns the HostHost derived key.
func (d Deriver) DeriveHostHost(dstHost string, key drkey.Key) (drkey.Key, error) {
	host, err := drkey.HostAddrFromString(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("deriving input H2H", err)
	}
	buf := make([]byte, 32)
	len := drkey.SerializeHostHostInput(buf, host)
	outKey, err := drkey.DeriveKey(buf[:len], key)
	return outKey, err
}

// serializeLevel2Input serializes the input for a ASHost or HostAS key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#protocol-specific-derivation
func (d Deriver) serializeLevel2Input(
	input []byte,
	derType drkey.KeyType,
	host drkey.HostAddr,
) int {

	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	input[1] = uint8(host.AddrType & 0x7)
	copy(input[2:], hostAddr)
	copy(input[2+l:inputLength], drkey.ZeroBlock[:])

	return inputLength
}

// serializeLevel1Input serializes the input for a Level1 key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#protocol-specific-derivation
func serializeLevel1Input(buf []byte, dstIA addr.IA) int {
	_ = buf[aes.BlockSize-1]
	buf[0] = byte(drkey.AsAs)
	binary.BigEndian.PutUint64(buf[1:], uint64(dstIA))
	copy(buf[9:], drkey.ZeroBlock[:])

	return aes.BlockSize
}
