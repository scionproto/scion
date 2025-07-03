// Copyright 2020 Anapaya Systems
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

package runner

import (
	"bytes"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/scionproto/scion/pkg/private/serrors"
)

func layerString(l gopacket.Layer) string {
	if l == nil {
		return "<nil>"
	}
	return gopacket.LayerString(l)
}

func compareLayers(act, exp gopacket.Layer) error {
	if act != nil && exp != nil && bytes.Equal(act.LayerContents(), exp.LayerContents()) {
		return nil
	}
	a := layerString(act)
	e := layerString(exp)
	var actContents, expContents []byte
	if act != nil {
		actContents = act.LayerContents()
	}
	if exp != nil {
		expContents = exp.LayerContents()
	}
	return serrors.New(fmt.Sprintf("String:\n%s\nBytes:\nExpected: %x\nActual:   %x",
		stringDiffPrettyPrint(a, e), expContents, actContents))
}

// normalizePacket applies the normalization function and returns the modified packet.
func normalizePacket(pkt gopacket.Packet, fn NormalizePacketFn) gopacket.Packet {
	fn(pkt)
	var lyrs []gopacket.SerializableLayer
	for _, layer := range pkt.Layers() {
		lyrs = append(lyrs, layer.(gopacket.SerializableLayer))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, lyrs...)
	if err != nil {
		panic(err)
	}
	packet := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	return packet
}

// DefaultNormalizePacket zeroes-out all the fields in the packet that can't
// generally be predicted by the test, both in received and in expected packet
// and thus makes them equal even if the field value varies among test runs.
func DefaultNormalizePacket(pkt gopacket.Packet) {
	for _, l := range pkt.Layers() {
		switch v := l.(type) {
		case *layers.IPv4:
			v.Id = 0
			v.Checksum = 0
		case *layers.UDP:
			v.Checksum = 0
		}
	}
}

func comparePkts(got, want gopacket.Packet, normalizeFn NormalizePacketFn) error {
	if got == nil || want == nil {
		return serrors.New("can not compare nil packets")
	}
	if normalizeFn != nil {
		got = normalizePacket(got, normalizeFn)
		want = normalizePacket(want, normalizeFn)
	}
	var err error
	var errors serrors.List
	for _, l := range got.Layers() {
		err = compareLayers(l, want.Layer(l.LayerType()))
		if err != nil {
			errors = append(errors, serrors.Wrap("layer mismatch", err))
		}
	}
	return errors.ToError()
}
