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

package layers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	LayerTypeHopByHopExtension = gopacket.RegisterLayerType(1101,
		gopacket.LayerTypeMetadata{Name: "HopByHopExtension", Decoder: nil})
	LayerTypeEndToEndExtension = gopacket.RegisterLayerType(1102,
		gopacket.LayerTypeMetadata{Name: "EndToEndExtension", Decoder: nil})
	LayerTypeSCIONUDP = gopacket.RegisterLayerType(1103,
		gopacket.LayerTypeMetadata{Name: "SCIONUDP", Decoder: nil})
	LayerTypeSCMP = gopacket.RegisterLayerType(1104,
		gopacket.LayerTypeMetadata{Name: "SCMP", Decoder: nil})
)

var (
	LayerToHeaderMap = map[gopacket.LayerType]common.L4ProtocolType{
		LayerTypeHopByHopExtension: common.HopByHopClass,
		LayerTypeEndToEndExtension: common.End2EndClass,
		LayerTypeSCIONUDP:          common.L4UDP,
		LayerTypeSCMP:              common.L4SCMP,
	}
)

var (
	zeroes = make([]byte, common.MaxMTU)
)

type Extension struct {
	layers.BaseLayer
	NextHeader common.L4ProtocolType
	NumLines   uint8
	Type       uint8
	Data       []byte
}

func (e *Extension) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < common.ExtnSubHdrLen {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCION Extension header, length too short", nil,
			"actual", len(data), "wanted", common.ExtnSubHdrLen)
	}
	expectedLength := int(data[1]) * common.LineLen
	if len(data) < expectedLength {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCION Extension body, length too short", nil,
			"actual", len(data), "wanted", expectedLength)
	}
	e.NextHeader = common.L4ProtocolType(data[0])
	e.NumLines = data[1]
	e.Type = data[2]
	e.Data = data[3:expectedLength]
	e.BaseLayer.Contents = data[:expectedLength]
	e.BaseLayer.Payload = data[expectedLength:]
	return nil
}

func (e *Extension) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	totalLength := common.ExtnSubHdrLen + len(e.Data)
	paddingSize := 0
	if opts.FixLengths {
		paddingSize = util.CalcPadding(totalLength, common.LineLen)
		totalLength += paddingSize
		e.NumLines = uint8(totalLength / common.LineLen)
	}
	bytes, err := b.PrependBytes(totalLength)
	if err != nil {
		return err
	}
	bytes[0] = uint8(e.NextHeader)
	bytes[1] = e.NumLines
	bytes[2] = e.Type
	copy(bytes[3:], e.Data)
	copy(bytes[3+len(e.Data):], zeroes[:paddingSize])
	return nil
}
