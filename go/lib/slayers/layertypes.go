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

package slayers

import (
	"github.com/google/gopacket"
)

var (
	LayerTypeSCION = gopacket.RegisterLayerType(
		1000,
		gopacket.LayerTypeMetadata{
			Name:    "SCION",
			Decoder: gopacket.DecodeFunc(decodeSCION),
		},
	)
	LayerTypeSCIONUDP = gopacket.RegisterLayerType(
		1001,
		gopacket.LayerTypeMetadata{
			Name:    "SCION/UDP",
			Decoder: gopacket.DecodeFunc(decodeSCIONUDP),
		},
	)
	LayerTypeSCMP = gopacket.RegisterLayerType(
		1002,
		gopacket.LayerTypeMetadata{
			Name:    "SCMP",
			Decoder: gopacket.DecodeFunc(decodeSCMP),
		},
	)
	LayerTypeSCMPDummy = gopacket.RegisterLayerType(
		2002,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPDummy",
			Decoder: gopacket.DecodeFunc(decodeSCMP),
		},
	)

	LayerTypeHopByHopExtn = gopacket.RegisterLayerType(
		1003,
		gopacket.LayerTypeMetadata{
			Name:    "HopByHopExtn",
			Decoder: gopacket.DecodeFunc(decodeHopByHopExtn),
		},
	)
	LayerTypeEndToEndExtn = gopacket.RegisterLayerType(
		1004,
		gopacket.LayerTypeMetadata{
			Name:    "EndToEndExtn",
			Decoder: gopacket.DecodeFunc(decodeEndToEndExtn),
		},
	)
	LayerTypeSCMPExternalInterfaceDown = gopacket.RegisterLayerType(
		1005,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPExternalInterfaceDown",
			Decoder: gopacket.DecodeFunc(decodeSCMPExternalInterfaceDown),
		},
	)
	LayerTypeSCMPInternalConnectivityDown = gopacket.RegisterLayerType(
		1006,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPInternalConnectivityDown",
			Decoder: gopacket.DecodeFunc(decodeSCMPInternalConnectivityDown),
		},
	)
	LayerTypeSCMPParameterProblem = gopacket.RegisterLayerType(
		1007,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPParameterProblem",
			Decoder: gopacket.DecodeFunc(decodeSCMPParameterProblem),
		},
	)
	LayerTypeSCMPDestinationUnreachable = gopacket.RegisterLayerType(
		1008,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPDestinationUnreachable",
			Decoder: gopacket.DecodeFunc(decodeSCMPDestinationUnreachable),
		},
	)
	LayerTypeSCMPPacketTooBig = gopacket.RegisterLayerType(
		1009,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPPacketTooBig",
			Decoder: gopacket.DecodeFunc(decodeSCMPPacketTooBig),
		},
	)
	LayerTypeSCMPEcho = gopacket.RegisterLayerType(
		1128,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPEcho",
			Decoder: gopacket.DecodeFunc(decodeSCMPEcho),
		},
	)
	LayerTypeSCMPTraceroute = gopacket.RegisterLayerType(
		1130,
		gopacket.LayerTypeMetadata{
			Name:    "SCMPTraceroute",
			Decoder: gopacket.DecodeFunc(decodeSCMPTraceroute),
		},
	)
)
