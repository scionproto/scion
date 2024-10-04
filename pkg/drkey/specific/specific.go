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
	"github.com/scionproto/scion/pkg/slayers"
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

	host, err := addr.ParseHost(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("parsing dst host", err)
	}
	buf := make([]byte, 32)
	l, err := d.serializeLevel2Input(buf, drkey.AsHost, host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey level 2 input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (p Deriver) DeriveHostAS(srcHost string, key drkey.Key) (drkey.Key, error) {
	host, err := addr.ParseHost(srcHost)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("parsing src host", err)
	}
	buf := make([]byte, 32)
	l, err := p.serializeLevel2Input(buf, drkey.HostAS, host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey level 2 input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// DeriveHostHost returns the HostHost derived key.
func (d Deriver) DeriveHostHost(dstHost string, key drkey.Key) (drkey.Key, error) {
	host, err := addr.ParseHost(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("deriving input H2H", err)
	}
	buf := make([]byte, 32)
	l, err := drkey.SerializeHostHostInput(buf, host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey host-host input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// serializeLevel2Input serializes the input for a ASHost or HostAS key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#protocol-specific-derivation
func (d Deriver) serializeLevel2Input(
	input []byte,
	derType drkey.KeyType,
	host addr.Host,
) (int, error) {

	typ, raw, err := slayers.PackAddr(host)
	if err != nil {
		return 0, serrors.Wrap("packing host address", err)
	}
	l := len(raw)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	input[1] = uint8(typ & 0xF)
	copy(input[2:], raw)
	copy(input[2+l:inputLength], drkey.ZeroBlock[:])

	return inputLength, nil
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
