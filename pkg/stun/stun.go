// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Copied from https://github.com/tailscale/tailscale/blob/main/net/stun/stun.go
// Modifications:
// - removed requirement for "software" attribute
// - use "fingerprint" attribute as identifying feature in Is() method
// - removed unused methods

// Package STUN parses STUN binding request packets and generates response packets.
package stun

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
)

const (
	attrNumFingerprint   = 0x8028
	attrXorMappedAddress = 0x0020
	bindingRequest       = "\x00\x01"
	magicCookie          = "\x21\x12\xa4\x42"
	lenFingerprint       = 8 // 2+byte header + 2-byte length + 4-byte crc32
	headerLen            = 20
)

// TxID is a transaction ID.
type TxID [12]byte

func fingerPrint(b []byte) uint32 { return crc32.ChecksumIEEE(b) ^ 0x5354554e }

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// ParseBindingRequest parses a STUN binding request.
func ParseBindingRequest(b []byte) (TxID, error) {
	if !Is(b) {
		return TxID{}, ErrNotSTUN
	}
	if string(b[:len(bindingRequest)]) != bindingRequest {
		return TxID{}, ErrNotBindingRequest
	}
	var txID TxID
	copy(txID[:], b[8:8+len(txID)])
	if err := foreachAttr(b[headerLen:], func(_ uint16, _ []byte) error { return nil }); err != nil {
		return TxID{}, err
	}
	return txID, nil
}

var (
	ErrNotSTUN           = errors.New("malformed STUN packet")
	ErrMalformedAttrs    = errors.New("STUN response has malformed attributes")
	ErrNotBindingRequest = errors.New("STUN request not a binding request")
	ErrNoFingerprint     = errors.New("STUN request didn't end in fingerprint")
	ErrWrongFingerprint  = errors.New("STUN request had bogus fingerprint")
)

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

// Response generates a binding response.
func Response(txID TxID, addrPort netip.AddrPort) []byte {
	addr := addrPort.Addr()

	var fam byte
	if addr.Is4() {
		fam = 1
	} else if addr.Is6() {
		fam = 2
	} else {
		return nil
	}
	attrsLen := 8 + addr.BitLen()/8
	b := make([]byte, 0, headerLen+attrsLen)

	// Header
	b = append(b, 0x01, 0x01) // success
	b = appendU16(b, uint16(attrsLen))
	b = append(b, magicCookie...)
	b = append(b, txID[:]...)

	// Attributes (well, one)
	b = appendU16(b, attrXorMappedAddress)
	b = appendU16(b, uint16(4+addr.BitLen()/8))
	b = append(b,
		0, // unused byte
		fam)
	b = appendU16(b, addrPort.Port()^0x2112) // first half of magicCookie
	ipa := addr.As16()
	for i, o := range ipa[16-addr.BitLen()/8:] {
		if i < 4 {
			b = append(b, o^magicCookie[i])
		} else {
			b = append(b, o^txID[i-len(magicCookie)])
		}
	}
	return b
}

// Is reports whether b is a STUN message.
func Is(b []byte) bool {
	if len(b) < headerLen {
		return false
	}
	if string(b[4:8]) != magicCookie {
		return false
	}
	// top two bits must be zero
	if b[0]&0b11000000 != 0 {
		return false
	}
	// check if packet has correct alignment
	if len(b)%4 != 0 {
		return false
	}
	// check if fingerprint attribute exists
	lastAttrib := binary.BigEndian.Uint16(b[len(b)-lenFingerprint : len(b)-lenFingerprint+2])
	lastAttribLen := binary.BigEndian.Uint16(b[len(b)-lenFingerprint+2 : len(b)-lenFingerprint+4])
	if lastAttrib != attrNumFingerprint || lastAttribLen != 4 {
		return false
	}
	// check if fingerprint correct
	wantFP := fingerPrint(b[:len(b)-lenFingerprint])
	gotFP := binary.BigEndian.Uint32(b[len(b)-4:])
	if wantFP != gotFP {
		return false
	}
	return true
}
