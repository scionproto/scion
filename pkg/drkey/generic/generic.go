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

package generic

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

// Deriver implements the level 2/3 generic drkey derivation.
type Deriver struct {
	Proto drkey.Protocol
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
	l, err := d.serializeLevel2Input(buf, drkey.AsHost, d.Proto, host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey level 2 input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (d Deriver) DeriveHostAS(
	srcHost string,
	key drkey.Key,
) (drkey.Key, error) {

	host, err := addr.ParseHost(srcHost)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("parsing src host", err)
	}
	buf := make([]byte, 32)
	l, err := d.serializeLevel2Input(buf, drkey.HostAS, d.Proto, host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey level 2 input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// DeriveHostHost returns the HostHost derived key.
func (d Deriver) DeriveHostHost(
	dstHost string,
	key drkey.Key,
) (drkey.Key, error) {

	host, err := addr.ParseHost(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("deriving input H2H", err)
	}
	buf := make([]byte, 32)
	l, err := drkey.SerializeHostHostInput(buf[:], host)
	if err != nil {
		return drkey.Key{}, serrors.Wrap("serializing drkey host-host input", err)
	}
	outKey, err := drkey.DeriveKey(buf[:l], key)
	return outKey, err
}

// serializeLevel2Input serializes the input for a ASHost or HostAS key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#generic-protocol-derivation
func (d Deriver) serializeLevel2Input(
	input []byte,
	derType drkey.KeyType,
	proto drkey.Protocol,
	host addr.Host,
) (int, error) {

	typ, raw, err := slayers.PackAddr(host)
	if err != nil {
		return 0, serrors.Wrap("packing host address", err)
	}
	l := len(raw)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (4+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	binary.BigEndian.PutUint16(input[1:], uint16(proto))
	input[3] = uint8(typ & 0xF)
	copy(input[4:], raw)
	copy(input[4+l:inputLength], drkey.ZeroBlock[:])

	return inputLength, nil
}
