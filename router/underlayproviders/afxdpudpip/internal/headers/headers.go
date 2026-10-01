// Copyright 2026 SCION Association
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

// Package headers builds and sizes the fixed Ethernet / IPv4 / IPv6 / UDP
// headers used by the afxdpudpip underlay. The implementation is specialized
// for SCION underlay traffic: no IPv4 options, no IPv6 extension headers,
// DF=1 on IPv4, hop limit / TTL 64. The header layouts follow RFC:
//   - (https://www.rfc-editor.org/rfc/rfc791)
//   - (https://www.rfc-editor.org/rfc/rfc8200)
//   - (https://www.rfc-editor.org/rfc/rfc768)
package headers

import (
	"encoding/binary"

	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
)

// Fixed header lengths (no options / extension headers).
const (
	LenEth  = 14
	LenIPv4 = 20
	LenIPv6 = 40
	LenUDP  = 8
)

// EtherTypes (See https://standards-oui.ieee.org/ethertype/eth.csv).
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
)

// IP protocol number
// (See https://www.iana.org/assignments/protocol-numbers).
const IPProtoUDP = 17

// defaultTTL is the IPv4 TTL / IPv6 Hop Limit written into outgoing packets.
// IPv4 requires a configurable fixed TTL
// (See https://www.rfc-editor.org/rfc/rfc1122#page-34);
// 64 was the recommended default in Assigned Numbers
// (See https://www.rfc-editor.org/rfc/rfc1700#page-64).
// IPv6 Neighbor Discovery uses the Assigned Numbers default for Cur Hop Limit as well:
// https://www.rfc-editor.org/rfc/rfc4861#section-6.3.2).
const defaultTTL = 64

// BuildEth writes a 14-byte Ethernet II header into buf (EtherType framing;
// RFC 894: https://www.rfc-editor.org/rfc/rfc894).
func BuildEth(buf []byte, dstMAC, srcMAC [6]byte, etherType uint16) {
	_ = buf[LenEth-1] // bounds-check elimination
	copy(buf[0:6], dstMAC[:])
	copy(buf[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(buf[12:14], etherType)
}

// BuildIPv4 writes a 20-byte IPv4 header (no options, DF=1, ID=0, TTL=64)
// into buf and computes the header checksum. totalLen is the IPv4 total
// length (header + payload, incl. UDP).
func BuildIPv4(buf []byte, srcIP, dstIP [4]byte, totalLen int) {
	_ = buf[LenIPv4-1]
	// Version 4, IHL 5
	buf[0] = 0x45
	// DSCP + ECN
	buf[1] = 0
	// Total length
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	// Identification
	binary.BigEndian.PutUint16(buf[4:6], 0)
	// Flags (DF=1) + Fragment offset 0
	binary.BigEndian.PutUint16(buf[6:8], 0x4000)
	// TTL
	buf[8] = defaultTTL
	// Protocol
	buf[9] = IPProtoUDP
	// Header checksum (filled below)
	buf[10] = 0
	buf[11] = 0
	copy(buf[12:16], srcIP[:])
	copy(buf[16:20], dstIP[:])
	binary.BigEndian.PutUint16(buf[10:12], checksum.IPv4Header(buf[:LenIPv4]))
}

// BuildIPv6 writes a 40-byte IPv6 header (traffic class 0, flow label 0,
// hop limit 64) into buf. payloadLen is the IPv6 payload length (everything
// after the IPv6 header, i.e. UDP header + payload).
func BuildIPv6(buf []byte, srcIP, dstIP [16]byte, payloadLen int) {
	_ = buf[LenIPv6-1]
	buf[0] = 0x60 // Version 6, traffic class high 4 bits 0
	buf[1] = 0    // Traffic class low 4 bits + flow label high 4 bits
	buf[2] = 0    // Flow label
	buf[3] = 0
	binary.BigEndian.PutUint16(buf[4:6], uint16(payloadLen))
	buf[6] = IPProtoUDP // Next header
	buf[7] = defaultTTL // Hop limit
	copy(buf[8:24], srcIP[:])
	copy(buf[24:40], dstIP[:])
}

// BuildUDP writes an 8-byte UDP header into buf with the checksum field
// zeroed. Callers that need a non-zero checksum (mandatory for IPv6;
// See https://datatracker.ietf.org/doc/html/rfc8200#section-8.1)
// must recompute it after the payload is in place using
// checksum.UDP6 or checksum.UDP6Pseudo.
func BuildUDP(buf []byte, srcPort, dstPort uint16, udpTotalLen int) {
	_ = buf[LenUDP-1]
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpTotalLen))
	buf[6] = 0
	buf[7] = 0
}
