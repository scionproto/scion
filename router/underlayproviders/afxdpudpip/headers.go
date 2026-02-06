// Copyright 2025 SCION Association
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package afxdpudpip

import "encoding/binary"

// buildIPv4Header writes a 20-byte IPv4 header (no options) into buf.
// totalLen is the IPv4 total length (header + payload).
func buildIPv4Header(buf []byte, srcIP, dstIP [4]byte, totalLen int) {
	buf[0] = 0x45                                          // Version (4) + IHL (5)
	buf[1] = 0                                             // DSCP + ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen)) // Total length
	binary.BigEndian.PutUint16(buf[4:6], 0)                // Identification
	binary.BigEndian.PutUint16(buf[6:8], 0x4000)           // Flags (DF) + Fragment offset
	buf[8] = 64                                            // TTL
	buf[9] = 17                                            // Protocol (UDP)
	buf[10] = 0                                            // Checksum (computed below)
	buf[11] = 0
	copy(buf[12:16], srcIP[:])
	copy(buf[16:20], dstIP[:])

	csum := ipv4Checksum(buf[:ipv4Len])
	binary.BigEndian.PutUint16(buf[10:12], csum)
}

// buildIPv6Header writes a 40-byte IPv6 header into buf.
// payloadLen is the IPv6 payload length (everything after the IPv6 header).
func buildIPv6Header(buf []byte, srcIP, dstIP [16]byte, payloadLen int) {
	buf[0] = 0x60 // Version (6) + Traffic class (high 4 bits)
	buf[1] = 0    // Traffic class (low 4 bits) + Flow label (high 4 bits)
	buf[2] = 0    // Flow label
	buf[3] = 0    // Flow label
	binary.BigEndian.PutUint16(buf[4:6], uint16(payloadLen))
	buf[6] = 17 // Next header (UDP)
	buf[7] = 64 // Hop limit
	copy(buf[8:24], srcIP[:])
	copy(buf[24:40], dstIP[:])
}

// buildUDPHeader writes an 8-byte UDP header into buf.
// udpLen is the UDP length (header + payload).
func buildUDPHeader(buf []byte, srcPort, dstPort uint16, totalLen int) {
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(totalLen))
	buf[6] = 0 // Checksum
	buf[7] = 0
}

// ipv4Checksum computes the ones-complement checksum over the IPv4 header.
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udp6Checksum computes the UDP checksum for IPv6 (mandatory per RFC 2460).
func udp6Checksum(srcIP, dstIP [16]byte, udpHdr []byte, payload []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP
	for i := 0; i < 16; i += 2 {
		sum += uint32(srcIP[i])<<8 | uint32(srcIP[i+1])
	}
	// Pseudo-header: dst IP
	for i := 0; i < 16; i += 2 {
		sum += uint32(dstIP[i])<<8 | uint32(dstIP[i+1])
	}
	// Pseudo-header: UDP length (32-bit)
	udpTotalLen := len(udpHdr) + len(payload)
	sum += uint32(udpTotalLen)
	// Pseudo-header: Next header (UDP = 17)
	sum += 17

	// UDP header (checksum field should be zeroed before calling)
	for i := 0; i+1 < len(udpHdr); i += 2 {
		sum += uint32(udpHdr[i])<<8 | uint32(udpHdr[i+1])
	}
	if len(udpHdr)%2 != 0 {
		sum += uint32(udpHdr[len(udpHdr)-1]) << 8
	}

	// Payload
	for i := 0; i+1 < len(payload); i += 2 {
		sum += uint32(payload[i])<<8 | uint32(payload[i+1])
	}
	if len(payload)%2 != 0 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xFFFF // UDP checksum 0 means "no checksum" in IPv4; use 0xFFFF for IPv6
	}
	return csum
}
