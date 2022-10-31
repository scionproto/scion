// Copyright 2022 ETH Zurich
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
type KeyType uint8

// Key types.
const (
	AsAs KeyType = iota
	AsHost
	HostAS
	HostHost
)

var (
	ZeroBlock [aes.BlockSize]byte
)

// HostAddr is the address representation of a host as defined in the SCION header.
type HostAddr struct {
	AddrType slayers.AddrType
	RawAddr  []byte
}

// AddrToString returns the string representation of the HostAddr.
func (h *HostAddr) String() string {
	switch h.AddrType {
	case slayers.T4Ip:
		return net.IP(h.RawAddr).String()
	case slayers.T4Svc:
		addr := addr.HostSVC(binary.BigEndian.Uint16(h.RawAddr[:addr.HostLenSVC]))
		return addr.String()
	case slayers.T16Ip:
		return net.IP(h.RawAddr).String()
	}
	return ""
}

// packtoHostAddr returns a HostAddr parsing a given address in string format.
func HostAddrFromString(host string) (HostAddr, error) {
	// trying IP
	ipAddr := addr.HostFromIPStr(host)
	if ipAddr != nil {
		if ip := ipAddr.IP().To4(); ip != nil {
			return HostAddr{
				AddrType: slayers.T4Ip,
				RawAddr:  ip,
			}, nil
		}
		return HostAddr{
			AddrType: slayers.T16Ip,
			RawAddr:  ipAddr.IP(),
		}, nil
	}
	// trying SVC
	svcAddr := addr.HostSVCFromString(host)
	if svcAddr != addr.SvcNone {
		return HostAddr{
			AddrType: slayers.T4Svc,
			RawAddr:  svcAddr.PackWithPad(2),
		}, nil
	}
	return HostAddr{}, serrors.New("unsupported address", "addr", host)
}

// SerializeHostHostInput serializes the input for deriving a HostHost key,
// as explained in
// https://docs.scion.org/en/latest/cryptography/drkey.html#level-derivation.
// This derivation is common for Generic and Specific derivations.
func SerializeHostHostInput(input []byte, host HostAddr) int {
	hostAddr := host.RawAddr
	l := len(hostAddr)

	// Calculate a multiple of 16 such that the input fits in
	nrBlocks := (2+l-1)/16 + 1

	inputLength := 16 * nrBlocks

	_ = input[inputLength-1]
	input[0] = uint8(HostHost)
	input[1] = uint8(host.AddrType & 0x7)
	copy(input[2:], hostAddr)
	copy(input[2+l:inputLength], ZeroBlock[:])

	return inputLength
}

// DeriveKey derives the following key given an input and a higher-level key,
// as stated in
// https://docs.scion.org/en/latest/cryptography/drkey.html#prf-derivation-specification
// The input buffer is overwritten.
func DeriveKey(input []byte, upperLevelKey Key) (Key, error) {
	var key Key
	b, err := initAESCBC(upperLevelKey[:])
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
	mode := cipher.NewCBCEncrypter(block, ZeroBlock[:])
	return mode, nil
}

func cbcMac(block cipher.BlockMode, b []byte) []byte {
	block.CryptBlocks(b, b)
	return b[len(b)-aes.BlockSize:]
}
