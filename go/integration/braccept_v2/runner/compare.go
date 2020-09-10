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

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/serrors"
)

func layerString(l gopacket.Layer) string {
	if l == nil {
		return "<nil>"
	}
	return gopacket.LayerString(l)
}

func compareLayersString(act, exp gopacket.Layer) error {
	a := layerString(act)
	e := layerString(exp)
	if a != e {
		return serrors.New(stringDiffPrettyPrint(a, e))
	}
	return nil
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

func comparePkts(got, want gopacket.Packet) error {
	if got == nil || want == nil {
		return serrors.New("can not compare nil packets")
	}
	var err error
	var errors serrors.List
	for _, l := range got.Layers() {
		switch v := l.(type) {
		case *layers.IPv4:
			w := want.Layer(layers.LayerTypeIPv4)
			w.(*layers.IPv4).Checksum = 0
			v.Id, v.Checksum = 0, 0
			err = compareLayersString(v, w)
			// TODO(karampok). Add IPv6
		case *layers.UDP:
			w := want.Layer(layers.LayerTypeUDP)
			w.(*layers.UDP).Checksum = 0
			v.Checksum = 0
			err = compareLayersString(v, w)
		case *layers.BFD:
			w := want.Layer(layers.LayerTypeBFD)
			w.(*layers.BFD).MyDiscriminator = 0
			v.MyDiscriminator = 0
			err = compareLayersString(v, w)
		default:
			err = compareLayers(v, want.Layer(v.LayerType()))
		}
		if err != nil {
			errors = append(errors, serrors.WrapStr("layer mismatch", err))
		}
	}
	return errors.ToError()
}
