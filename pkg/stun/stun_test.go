// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Copied and modified from https://github.com/tailscale/tailscale/blob/main/net/stun/stun_test.go

package stun_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/stun"
)

const (
	attrNumSoftware      = 0x8022
	attrNumFingerprint   = 0x8028
	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
	bindingRequest       = "\x00\x01"
	magicCookie          = "\x21\x12\xa4\x42"
	lenFingerprint       = 8 // 2+byte header + 2-byte length + 4-byte crc32
	headerLen            = 20
	software             = "test1234"
)

var (
	ErrNotSTUN            = errors.New("malformed STUN packet")
	ErrMalformedAttrs     = errors.New("STUN response has malformed attributes")
	ErrNotSuccessResponse = errors.New("STUN packet is not a response")
)

func newTxID() stun.TxID {
	var tx stun.TxID
	if _, err := crand.Read(tx[:]); err != nil {
		panic(err)
	}
	return tx
}

// Request generates a binding request STUN packet.
// The transaction ID, tID, should be a random sequence of bytes.
func request(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenFingerprint)) // number of bytes following header
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := fingerPrint(b)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	return b
}

func requestWithoutFingerprint(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	return b
}

func requestWrongFingerprint(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenFingerprint)) // number of bytes following header
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := uint32(10)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	return b
}

func requestUnknownAttribute(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	const lenAttrSoftware = 4 + len(software)
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenFingerprint+lenAttrSoftware)) // number of bytes following header
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute SOFTWARE, RFC5389 Section 15.5.
	b = appendU16(b, attrNumSoftware)
	b = appendU16(b, uint16(len(software)))
	b = append(b, software...)

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := fingerPrint(b)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	return b
}

func requestFingerprintNotLastAttribute(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	const lenAttrSoftware = 4 + len(software)
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenFingerprint+lenAttrSoftware)) // number of bytes following header
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := fingerPrint(b)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	// Attribute SOFTWARE, RFC5389 Section 15.5.
	b = appendU16(b, attrNumSoftware)
	b = appendU16(b, uint16(len(software)))
	b = append(b, software...)

	return b
}

func requestMalformedAttribute(tID stun.TxID) []byte {
	// STUN header, RFC5389 Section 6.
	const lenAttrSoftware = 4 + len(software)
	b := make([]byte, 0, headerLen+lenFingerprint)
	b = append(b, bindingRequest...)
	b = appendU16(b, uint16(lenFingerprint+lenAttrSoftware)+1) // number of bytes following header
	b = append(b, magicCookie...)
	b = append(b, tID[:]...)

	// Attribute SOFTWARE, RFC5389 Section 15.5.
	b = appendU16(b, attrNumSoftware)
	b = appendU16(b, uint16(len(software)))
	b = append(b, software...)
	b = append(b, byte(200))

	// Attribute FINGERPRINT, RFC5389 Section 15.5.
	fp := fingerPrint(b)
	b = appendU16(b, attrNumFingerprint)
	b = appendU16(b, 4)
	b = appendU32(b, fp)

	return b
}

// ParseResponse parses a successful binding response STUN packet.
// The IP address is extracted from the XOR-MAPPED-ADDRESS attribute.
func parseResponse(b []byte) (tID stun.TxID, addr netip.AddrPort, err error) {
	if !is(b) {
		return tID, netip.AddrPort{}, ErrNotSTUN
	}
	copy(tID[:], b[8:8+len(tID)])
	if b[0] != 0x01 || b[1] != 0x01 {
		return tID, netip.AddrPort{}, ErrNotSuccessResponse
	}
	attrsLen := int(binary.BigEndian.Uint16(b[2:4]))
	b = b[headerLen:] // remove STUN header
	if attrsLen > len(b) {
		return tID, netip.AddrPort{}, ErrMalformedAttrs
	} else if len(b) > attrsLen {
		b = b[:attrsLen] // trim trailing packet bytes
	}

	var fallbackAddr netip.AddrPort

	// Read through the attributes.
	// The the addr+port reported by XOR-MAPPED-ADDRESS
	// as the canonical value. If the attribute is not
	// present but the STUN server responds with
	// MAPPED-ADDRESS we fall back to it.
	if err := foreachAttr(b, func(attrType uint16, attr []byte) error {
		switch attrType {
		case attrXorMappedAddress:
			ipSlice, port, err := xorMappedAddress(tID, attr)
			if err != nil {
				return err
			}
			if ip, ok := netip.AddrFromSlice(ipSlice); ok {
				addr = netip.AddrPortFrom(ip.Unmap(), port)
			}
		case attrMappedAddress:
			ipSlice, port, err := mappedAddress(attr)
			if err != nil {
				return ErrMalformedAttrs
			}
			if ip, ok := netip.AddrFromSlice(ipSlice); ok {
				fallbackAddr = netip.AddrPortFrom(ip.Unmap(), port)
			}
		}
		return nil

	}); err != nil {
		return stun.TxID{}, netip.AddrPort{}, err
	}

	if addr.IsValid() {
		return tID, addr, nil
	}
	if fallbackAddr.IsValid() {
		return tID, fallbackAddr, nil
	}
	return tID, netip.AddrPort{}, ErrMalformedAttrs
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func fingerPrint(b []byte) uint32 { return crc32.ChecksumIEEE(b) ^ 0x5354554e }

func TestIs(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", false},
		{"\x00\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", false},
		{"\x00\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", true},
		{"\x00\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00foo", true},
		// high bits set:
		{"\xf0\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", false},
		{"\x40\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", false},
		// first byte non-zero, but not high bits:
		{"\x20\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", true},
	}
	for i, tt := range tests {
		pkt := []byte(tt.in)
		got := stun.Is(pkt)
		if got != tt.want {
			t.Errorf("%d. In(%q (%v)) = %v; want %v", i, pkt, pkt, got, tt.want)
		}
	}
}

func TestParseBindingRequest(t *testing.T) {
	tx := newTxID()
	req := request(tx)
	gotTx, err := stun.ParseBindingRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if gotTx != tx {
		t.Errorf("original txID %q != got txID %q", tx, gotTx)
	}

	req = []byte("\x00\x00\x00\x00" + magicCookie + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00") // not STUN
	gotTx, err = stun.ParseBindingRequest(req)
	if err == nil {
		t.Error("Expected error \"malformed STUN packet\". No error thrown.")
	}

	tx = newTxID()
	req = requestWithoutFingerprint(tx)
	gotTx, err = stun.ParseBindingRequest(req)
	if err == nil {
		t.Error("Expected error \"STUN request didn't end in fingerprint\". No error thrown.")
	}

	tx = newTxID()
	req = requestWrongFingerprint(tx)
	gotTx, err = stun.ParseBindingRequest(req)
	if err == nil {
		t.Error("Expected error \"STUN request had bogus fingerprint\". No error thrown.")
	}

	tx = newTxID()
	req = requestUnknownAttribute(tx)
	gotTx, err = stun.ParseBindingRequest(req)
	if err != nil {
		// Unknown comprehension-optional attributes MUST be ignored by the agent. - RFC8489
		t.Errorf("Expected no error. Got error:%v", err)
	}
	if gotTx != tx {
		t.Errorf("original txID %q != got txID %q", tx, gotTx)
	}

	tx = newTxID()
	req = requestFingerprintNotLastAttribute(tx)
	gotTx, err = stun.ParseBindingRequest(req)
	if err == nil {
		t.Error("Expected error \"STUN request didn't end in fingerprint\". No error thrown.")
	}

	tx = newTxID()
	req = requestMalformedAttribute(tx)
	gotTx, err = stun.ParseBindingRequest(req)
	if err == nil {
		t.Error("Expected error \"STUN response has malformed attributes\". No error thrown.")
	}
}

func TestResponse(t *testing.T) {
	txN := func(n int) (x stun.TxID) {
		for i := range x {
			x[i] = byte(n)
		}
		return
	}
	tests := []struct {
		tx   stun.TxID
		addr netip.Addr
		port uint16
	}{
		{tx: txN(1), addr: netip.MustParseAddr("1.2.3.4"), port: 254},
		{tx: txN(2), addr: netip.MustParseAddr("1.2.3.4"), port: 257},
		{tx: txN(3), addr: netip.MustParseAddr("1::4"), port: 254},
		{tx: txN(4), addr: netip.MustParseAddr("1::4"), port: 257},
	}
	for _, tt := range tests {
		res := stun.Response(tt.tx, netip.AddrPortFrom(tt.addr, tt.port))
		tx2, addr2, err := parseResponse(res)
		if err != nil {
			t.Errorf("TX %x: error: %v", tt.tx, err)
			continue
		}
		if tt.tx != tx2 {
			t.Errorf("TX %x: got TxID = %v", tt.tx, tx2)
		}
		if tt.addr.Compare(addr2.Addr()) != 0 {
			t.Errorf("TX %x: addr = %v; want %v", tt.tx, addr2.Addr(), tt.addr)
		}
		if tt.port != addr2.Port() {
			t.Errorf("TX %x: port = %v; want %v", tt.tx, addr2.Port(), tt.port)
		}
	}
}

func foreachAttr(b []byte, fn func(attrType uint16, a []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return ErrMalformedAttrs
		}
		attrType := binary.BigEndian.Uint16(b[:2])
		attrLen := int(binary.BigEndian.Uint16(b[2:4]))
		attrLenWithPad := (attrLen + 3) &^ 3
		b = b[4:]
		if attrLenWithPad > len(b) {
			return ErrMalformedAttrs
		}
		if err := fn(attrType, b[:attrLen]); err != nil {
			return err
		}
		b = b[attrLenWithPad:]
	}
	return nil
}

func xorMappedAddress(tID stun.TxID, b []byte) (addr []byte, port uint16, err error) {
	// XOR-MAPPED-ADDRESS attribute, RFC5389 Section 15.2
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	xorPort := binary.BigEndian.Uint16(b[2:4])
	addrField := b[4:]
	port = xorPort ^ 0x2112 // first half of magicCookie

	addrLen := familyAddrLen(b[1])
	if addrLen == 0 {
		return nil, 0, ErrMalformedAttrs
	}
	if len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	xorAddr := addrField[:addrLen]
	addr = make([]byte, addrLen)
	for i := range xorAddr {
		if i < len(magicCookie) {
			addr[i] = xorAddr[i] ^ magicCookie[i]
		} else {
			addr[i] = xorAddr[i] ^ tID[i-len(magicCookie)]
		}
	}
	return addr, port, nil
}

func familyAddrLen(fam byte) int {
	switch fam {
	case 0x01: // IPv4
		return net.IPv4len
	case 0x02: // IPv6
		return net.IPv6len
	default:
		return 0
	}
}

func mappedAddress(b []byte) (addr []byte, port uint16, err error) {
	if len(b) < 4 {
		return nil, 0, ErrMalformedAttrs
	}
	port = uint16(b[2])<<8 | uint16(b[3])
	addrField := b[4:]
	addrLen := familyAddrLen(b[1])
	if addrLen == 0 {
		return nil, 0, ErrMalformedAttrs
	}
	if len(addrField) < addrLen {
		return nil, 0, ErrMalformedAttrs
	}
	return bytes.Clone(addrField[:addrLen]), port, nil
}

func is(b []byte) bool {
	return len(b) >= headerLen &&
		b[0]&0b11000000 == 0 && // top two bits must be zero
		string(b[4:8]) == magicCookie
}
