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
)

const (
	SCMPHeaderAndMetaLength = 24
)

// FIXME(scrye): add checksum support
type SCMP struct {
	layers.BaseLayer

	ClassType uint32
	Length    uint16
	Checksum  uint16
	Timestamp uint64

	InfoBlockLines       uint8
	CommonHeaderLines    uint8
	AddressHeaderLines   uint8
	PathHeaderLines      uint8
	ExtensionHeaderLines uint8
	L4Lines              uint8
	L4ProtoType          common.L4ProtocolType
	Padding              uint8

	InfoBlock            []byte
	CommonHeaderBlock    []byte
	AddressHeaderBlock   []byte
	PathHeaderBlock      []byte
	ExtensionHeaderBlock []byte
	L4Block              []byte

	CustomPayload []byte
}

func (s *SCMP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < SCMPHeaderAndMetaLength {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCMP header, length too short", nil,
			"actual", len(data), "wanted", 16)
	}
	s.ClassType = common.Order.Uint32(data[0:4])
	s.Length = common.Order.Uint16(data[4:6])
	s.Checksum = common.Order.Uint16(data[6:8])
	s.Timestamp = common.Order.Uint64(data[8:16])
	s.InfoBlockLines = data[16]
	s.CommonHeaderLines = data[17]
	s.AddressHeaderLines = data[18]
	s.PathHeaderLines = data[19]
	s.ExtensionHeaderLines = data[20]
	s.L4Lines = data[21]
	s.L4ProtoType = common.L4ProtocolType(data[22])
	s.Padding = data[23]

	if len(data) < int(s.Length) {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCMP message, length too short", nil,
			"actual", len(data), "wanted", s.Length)
	}
	offset := SCMPHeaderAndMetaLength
	infoBlockLength := getLength(s.InfoBlockLines)
	commonHeaderLength := getLength(s.CommonHeaderLines)
	addressHeaderLength := getLength(s.AddressHeaderLines)
	pathHeaderLength := getLength(s.PathHeaderLines)
	extensionHeaderLength := getLength(s.ExtensionHeaderLines)
	l4Length := getLength(s.L4Lines)
	totalQuoteLength := infoBlockLength + commonHeaderLength + addressHeaderLength +
		pathHeaderLength + extensionHeaderLength + l4Length
	if int(s.Length) < totalQuoteLength+SCMPHeaderAndMetaLength {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCMP data, quotes extend past total length", nil,
			"actual", int(s.Length)-SCMPHeaderAndMetaLength, "wanted", totalQuoteLength)
	}
	s.InfoBlock = data[offset : offset+infoBlockLength]
	offset += infoBlockLength
	s.CommonHeaderBlock = data[offset : offset+commonHeaderLength]
	offset += commonHeaderLength
	s.AddressHeaderBlock = data[offset : offset+addressHeaderLength]
	offset += addressHeaderLength
	s.PathHeaderBlock = data[offset : offset+pathHeaderLength]
	offset += pathHeaderLength
	s.ExtensionHeaderBlock = data[offset : offset+extensionHeaderLength]
	offset += extensionHeaderLength
	s.L4Block = data[offset : offset+l4Length]
	offset += l4Length
	s.CustomPayload = data[offset:s.Length]
	return nil
}

func (s *SCMP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	totalQuoteLength := len(s.InfoBlock) + len(s.CommonHeaderBlock) + len(s.AddressHeaderBlock) +
		len(s.PathHeaderBlock) + len(s.ExtensionHeaderBlock) + len(s.L4Block) + len(s.CustomPayload)
	totalPacketLength := SCMPHeaderAndMetaLength + totalQuoteLength
	if totalPacketLength > 0xffff {
		return common.NewBasicError("packet too large", nil, "length", totalPacketLength,
			"max_allowed", uint16(0xffff))
	}
	if opts.FixLengths {
		if err := checkAligned(s.InfoBlock, "info block"); err != nil {
			return err
		}
		if err := checkAligned(s.CommonHeaderBlock, "common header quote"); err != nil {
			return err
		}
		if err := checkAligned(s.AddressHeaderBlock, "address header quote"); err != nil {
			return err
		}
		if err := checkAligned(s.PathHeaderBlock, "path header quote"); err != nil {
			return err
		}
		if err := checkAligned(s.ExtensionHeaderBlock, "extension header quote"); err != nil {
			return err
		}
		if err := checkAligned(s.L4Block, "L4 header quote"); err != nil {
			return err
		}
		s.Length = uint16(totalPacketLength)
		s.InfoBlockLines = uint8(len(s.InfoBlock)) / common.LineLen
		s.CommonHeaderLines = uint8(len(s.CommonHeaderBlock)) / common.LineLen
		s.AddressHeaderLines = uint8(len(s.AddressHeaderBlock)) / common.LineLen
		s.PathHeaderLines = uint8(len(s.PathHeaderBlock)) / common.LineLen
		s.ExtensionHeaderLines = uint8(len(s.ExtensionHeaderBlock)) / common.LineLen
		s.L4Lines = uint8(len(s.L4Block)) / common.LineLen
	}
	bytes, err := b.PrependBytes(totalPacketLength)
	if err != nil {
		return err
	}
	common.Order.PutUint32(bytes[0:4], s.ClassType)
	common.Order.PutUint16(bytes[4:6], s.Length)
	common.Order.PutUint16(bytes[6:8], s.Checksum)
	common.Order.PutUint64(bytes[8:16], s.Timestamp)
	bytes[16] = s.InfoBlockLines
	bytes[17] = s.CommonHeaderLines
	bytes[18] = s.AddressHeaderLines
	bytes[19] = s.PathHeaderLines
	bytes[20] = s.ExtensionHeaderLines
	bytes[21] = s.L4Lines
	bytes[22] = byte(s.L4ProtoType)
	bytes[23] = s.Padding
	offset := SCMPHeaderAndMetaLength
	offset += copy(bytes[offset:], s.InfoBlock)
	offset += copy(bytes[offset:], s.CommonHeaderBlock)
	offset += copy(bytes[offset:], s.AddressHeaderBlock)
	offset += copy(bytes[offset:], s.PathHeaderBlock)
	offset += copy(bytes[offset:], s.ExtensionHeaderBlock)
	offset += copy(bytes[offset:], s.L4Block)
	offset += copy(bytes[offset:], s.CustomPayload)
	return nil
}

func checkAligned(b []byte, section string) error {
	maxLength := common.LineLen * 0xff
	if len(b)%common.LineLen != 0 {
		return common.NewBasicError("cannot fix length, SCMP section is not aligned", nil,
			"section", section, "length", len(b), "must_be_multiple_of", common.LineLen)
	}
	if len(b) > maxLength {
		return common.NewBasicError("cannot fix length, SCMP section is too long", nil,
			"section", section, "length", len(b), "max_length", maxLength)
	}
	return nil
}

func getLength(numLines uint8) int {
	return int(numLines) * common.LineLen
}
