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

package drkey

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

// keyType represents the different types of keys (host->AS, AS->host, host->host).
type keyType uint8

// Key types.
const (
	asToAs keyType = iota
	asToHost
	hostToAS
	hostToHost
)

var (
	zeroBlock [aes.BlockSize]byte
)

// hostAddr is the address representation of a host as defined in the SCION header.
type hostAddr struct {
	AddrLen  slayers.AddrLen
	AddrType slayers.AddrType
	RawAddr  []byte
}

// packtoHostAddr returns a HostAddr parsing a given address in string format.
func packtoHostAddr(host string) (hostAddr, error) {
	// trying IP
	ipAddr := addr.HostFromIPStr(host)
	if ipAddr != nil {
		if ip := ipAddr.IP().To4(); ip != nil {
			return hostAddr{
				AddrLen:  slayers.AddrLen4,
				AddrType: slayers.T4Ip,
				RawAddr:  ip,
			}, nil
		}
		return hostAddr{
			AddrLen:  slayers.AddrLen16,
			AddrType: slayers.T16Ip,
			RawAddr:  ipAddr.IP(),
		}, nil
	}
	// trying SVC
	svcAddr := addr.HostSVCFromString(host)
	if svcAddr != addr.SvcNone {
		return hostAddr{
			AddrLen:  slayers.AddrLen4,
			AddrType: slayers.T4Svc,
			RawAddr:  svcAddr.PackWithPad(2),
		}, nil
	}
	return hostAddr{}, serrors.New("unsupported address", "addr", host)
}

// AddrToString returns the string representation of the HostAddr.
func (h *hostAddr) AddrToString() string {
	switch h.AddrLen {
	case slayers.AddrLen4:
		switch h.AddrType {
		case slayers.T4Ip:
			addr := &net.IPAddr{IP: net.IP(h.RawAddr)}
			return addr.String()
		case slayers.T4Svc:
			addr := addr.HostSVC(binary.BigEndian.Uint16(h.RawAddr[:addr.HostLenSVC]))
			return addr.String()
		}
	case slayers.AddrLen16:
		switch h.AddrType {
		case slayers.T16Ip:
			addr := &net.IPAddr{IP: net.IP(h.RawAddr)}
			return addr.String()
		}
	}
	return ""
}

func inputDeriveHostToHost(input []byte, host hostAddr) int {
	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1

	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(hostToHost)
	input[1] = uint8(host.AddrType&0x3)<<2 | uint8(host.AddrLen&0x3)
	copy(input[2:], hostAddr)
	copy(input[2+l:inputLength], zeroBlock[:])

	return inputLength
}

// DeriveKey derives the following key given an input and a higher-level key.
// The input buffer is overwritten.
func deriveKey(input []byte, upKey Key) (Key, error) {
	var key Key
	b, err := initAESCBC(upKey[:])
	if err != nil {
		return key, err
	}
	mac := cbcMac(b, input[:])
	copy(key[:], mac)
	return key, nil
}

func initAESCBC(key []byte) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.New("Unable to initialize AES cipher")
	}
	mode := cipher.NewCBCEncrypter(block, zeroBlock[:])
	return mode, nil
}

func cbcMac(block cipher.BlockMode, b []byte) []byte {
	block.CryptBlocks(b, b)
	return b[len(b)-aes.BlockSize:]
}
