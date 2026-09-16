// Copyright 2026 ETH Zurich
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

package path

import (
	"crypto/cipher"

	"github.com/scionproto/scion/pkg/addr"
	dppath "github.com/scionproto/scion/pkg/slayers/path"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
)

func (r *Reservation) SetScionPath(dec *scion.Decoded) error {
	return r.setScionPath(dec)
}

func (r *Reservation) GetScionMACs() [][dppath.MacLen]byte {
	return r.scionMacs
}

func (r *Reservation) AesBlocks() *[]cipher.Block {
	return &r.blocksPerAk
}

func NewHopBitSet(buff []byte, nBits int) hopBitset {
	return newHopBitset(buff, nBits)
}

func LenOfSerializedHops(hops []*Hop) int {
	return lenOfSerializedHops(hops)
}

func SerializeHops(buff []byte, hops []*Hop) (int, error) {
	return serializeHops(buff, hops)
}

func DeserializeHops(buff []byte) ([]*Hop, error) {
	return deserializeHops(buff)
}

func (r *Reservation) SetupWithHummDecoded(
	dec *dphum.Decoded,
	dstIA addr.IA,
	seq FlyoverSequence,
) error {
	return r.setupReservationWithHummDecoded(dec, dstIA, seq)
}

func HummDataplaneToBaseHops(dec *dphum.Decoded) ([]BaseHop, []uint8, error) {
	return hummDataplaneToBaseHops(dec)
}
