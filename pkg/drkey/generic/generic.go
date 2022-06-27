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

package generic

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// Deriver implements the level 2/3 generic drkey derivation.
type Deriver struct {
	// buf is a 32-byte inteded to save some allocations. Internally, it is used
	// as dst buffer for the input generation functions and as input buffer for
	// the key derivation functions.
	buf [32]byte
}

// serializeLevel2Input serializes the input for a ASHost or HostAS key,
// as explained in https://docs.scion.org/en/latest/cryptography/drkey.html#generic-protocol-derivation
func (d *Deriver) serializeLevel2Input(input []byte, derType drkey.KeyType,
	proto drkey.Protocol, host drkey.HostAddr) int {
	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (4+l-1)/16 + 1
	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(derType)
	binary.BigEndian.PutUint16(input[1:], uint16(proto))
	input[3] = uint8(host.AddrType&0x3)<<2 | uint8(host.AddrLen&0x3)
	copy(input[4:], hostAddr)
	copy(input[4+l:inputLength], drkey.ZeroBlock[:])

	return inputLength
}

// DeriveASHost returns the ASHost derived key.
func (d *Deriver) DeriveASHost(proto drkey.Protocol, dstHost string,
	key drkey.Key) (drkey.Key, error) {
	host, err := drkey.HostAddrFromString(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("parsing dst host", err)
	}
	len := d.serializeLevel2Input(d.buf[:], drkey.AsToHost, proto, host)
	outKey, err := drkey.DeriveKey(d.buf[:len], key)
	return outKey, err
}

// DeriveHostAS returns the HostAS derived key.
func (d *Deriver) DeriveHostAS(proto drkey.Protocol, srcHost string,
	key drkey.Key) (drkey.Key, error) {
	host, err := drkey.HostAddrFromString(srcHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("parsing src host", err)
	}
	len := d.serializeLevel2Input(d.buf[:], drkey.HostToAS, proto, host)
	outKey, err := drkey.DeriveKey(d.buf[:len], key)
	return outKey, err
}

// DeriveHostToHost returns the HostHost derived key.
func (d *Deriver) DeriveHostToHost(dstHost string,
	key drkey.Key) (drkey.Key, error) {
	host, err := drkey.HostAddrFromString(dstHost)
	if err != nil {
		return drkey.Key{}, serrors.WrapStr("deriving input H2H", err)
	}
	len := drkey.SerializeHostToHostInput(d.buf[:], host)
	outKey, err := drkey.DeriveKey(d.buf[:len], key)
	return outKey, err
}
