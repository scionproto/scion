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

/*
Package slayers contains gopacket style layers for the SCION Header, HopByHop and EndToEnd Extension
headers, SCMP, and SCION/UDP.

# Basic Decoding

There are multiple ways to decode a SCION packet. If performance is of no concern a new
gopacket.Packet can be instantiated:

	// Eagerly decode an entire SCION packet
	packet := gopacket.NewPacket(raw, LayerTypeSCION, gopacket.Default)
	// Access the SCION header
	if scnL := packet.Layer(LayerTypeSCION); scnL != nil {
		fmt.Println("This is a SCION packet.")
		// Access the actual SCION data from this layer
		s := scnL.(*slayers.SCION) // Guaranteed to work
		fmt.Printf("From %s to %s\n", s.SrcIA, s.DstIA)
	}
	// Similarly, a SCION/UDP payload can be accessed
	if udpL := packet.Layer(LayerTypeSCIONUDP); udpL != nil {
		u := udpL.(*slayers.UDP) // Guaranteed to work
		fmt.Printf("From %d to %d\n", u.SrcPort, u.DstPort)
	}

# Decoding using gopacket.DecodingLayerParser

Decoding using gopacket.DecodingLayerParser can yield speed ups for more than 10x compared to eager
decoding. The following can be used to decode any SCION packet (including HBH and E2E extension)
that have either a SCION/UDP or SCMP payload:

	var scn slayers.SCION
	var hbh slayers.HopByHopExtnSkipper
	var e2e slayers.EndToEndExtnSkipper
	var udp slayers.UDP
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(LayerTypeSCION, &scn, &hbh, &e2e, &udp, &scmp, &pld)
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(packetData, &decoded); err != nil {
		// Handle error
	}
	for _, layerType := range decoded {
		// Handle layers
	}

The important thing to note here is that the parser is modifying the passed in layers (scn, hbh,
e2e, udp, scmp) instead of allocating new ones, thus greatly speeding up the decoding process. It's
even branching based on layer type... it'll handle an (scn, e2e, udp) or (scn, hbh, scmp) stack.

Note: Great care has been taken to only lazily parse the SCION header, however, HBH and E2E
extensions are currently eagerly parsed (if they exist). Thus, handling packets containing these
extensions will be much slower (see the package benchmarks for reference).
When using the DecodingLayerParser, the extensions can be explicitly skipped by using the
HopByHop/EndToEndExtnSkipper layer. The content of this Skipper-layer can be decoded into the full
representation when necessary.

# Creating Packet Data

Packet data can be created by instantiating the various slayers.* types. To generate an empty
(and useless) SCION(HBH(UDP(Payload))) packet, for example, you can run:

	s := &slayers.SCION{}
	hbh := &slayers.HopByHopExtn{}
	udp := &slayers.UDP{}
	pld := gopacket.Payload([]byte{1, 2, 3, 4}))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, s, hbh, udp, pld); err != nil {
		// Handle error
	}
	packedData := buf.Bytes()

BFD and gopacket/layers

slayers does intentionally not import gopacket/layers, as this contains a
considerable amount of bloat in the form of layer types that are never used by
most users of the slayers package.
At the same time, the slayers.SCION layer supports parsing SCION/BFD packets
using the gopacket/layers.BFD layer type. Applications that want to parse
SCION/BFD packets need to ensure that gopacket/layers is imported somewhere in
the application so that the corresponding layer decoder is registered. Note
that this is naturally ensured when using the DecodingLayer style.
*/
package slayers
