// Copyright 2018 ETH Zurich
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

package main

import (
	"github.com/scionproto/scion/go/border/braccept/parser"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/common"
)

type DevTaggedLayers struct {
	Dev          string
	TaggedLayers parser.TaggedLayers
}

func AllocatePacket() *DevTaggedLayers {
	return &DevTaggedLayers{}
}

func AllocatePackets(n uint) []*DevTaggedLayers {
	return make([]*DevTaggedLayers, n)
}

func (dtl *DevTaggedLayers) ParsePacket(packetString string) {
	dtl.TaggedLayers = parser.ParsePacket(packetString)
}

func (dtl *DevTaggedLayers) CloneAndUpdate(packetString string) *DevTaggedLayers {
	clone := &DevTaggedLayers{Dev: dtl.Dev}
	clone.TaggedLayers = dtl.TaggedLayers.CloneAndUpdate(packetString)
	return clone
}

func (dtl *DevTaggedLayers) SetDev(dev string) {
	dtl.Dev = dev
}

func (dtl *DevTaggedLayers) SetChecksum(l4Tag, l3Tag string) {
	dtl.TaggedLayers.SetChecksum(l4Tag, l3Tag)
}

func (dtl *DevTaggedLayers) Serialize() common.RawBytes {
	return dtl.TaggedLayers.Serialize()
}

func (dtl *DevTaggedLayers) GenerateMac(scnTag string, infTag, hfTag, hfMacTag string) {
	dtl.TaggedLayers.GenerateMac(scnTag, shared.HashMac, infTag, hfTag, hfMacTag)
}

func (dtl *DevTaggedLayers) String() string {
	return dtl.TaggedLayers.String()
}
