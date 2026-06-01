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

//go:build linux && (amd64 || arm64)

package afxdpudpip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unsafe"

	"github.com/scionproto/scion/router"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/headers"
)

type packetGolden struct {
	Name       string `json:"name"`
	LinkType   string `json:"link_type"`
	Family     string `json:"family"`
	Local      string `json:"local"`
	Remote     string `json:"remote"`
	SrcMAC     string `json:"src_mac"`
	DstMAC     string `json:"dst_mac"`
	PayloadHex string `json:"payload_hex"`
}

type goldenCase struct {
	meta    packetGolden
	local   netip.AddrPort
	remote  netip.AddrPort
	srcMAC  net.HardwareAddr
	dstMAC  net.HardwareAddr
	payload []byte
	frame   []byte
}

func TestFinishPacketMatchesGolden(t *testing.T) {
	for _, tc := range loadGoldenCases(t) {
		t.Run(tc.meta.Name, func(t *testing.T) {
			got := buildLinkFrame(t, tc, false)
			if !bytes.Equal(got, tc.frame) {
				diffDump(t, tc.meta.Name, tc.frame, got)
			}
		})
	}
}

func TestHeaderAndChecksumBuildersMatchGolden(t *testing.T) {
	for _, tc := range loadGoldenCases(t) {
		t.Run(tc.meta.Name, func(t *testing.T) {
			got := buildWithHeadersAndChecksum(t, tc)
			if !bytes.Equal(got, tc.frame) {
				diffDump(t, tc.meta.Name, tc.frame, got)
			}
		})
	}
}

func TestIPv6OffloadSeedMatchesPseudoHeader(t *testing.T) {
	for _, tc := range loadGoldenCases(t) {
		if tc.meta.Family != "ipv6" {
			continue
		}
		t.Run(tc.meta.Name, func(t *testing.T) {
			want := append([]byte(nil), tc.frame...)
			udpOff := headers.LenEth + headers.LenIPv6
			seed := checksum.UDP6Pseudo(tc.local.Addr().As16(), tc.remote.Addr().As16(),
				headers.LenUDP+len(tc.payload))
			binary.BigEndian.PutUint16(want[udpOff+6:udpOff+8], seed)

			got := buildLinkFrame(t, tc, true)
			if !bytes.Equal(got, want) {
				diffDump(t, tc.meta.Name, want, got)
			}
		})
	}
}

func loadGoldenCases(t *testing.T) []goldenCase {
	t.Helper()

	names := []string{
		"internal_ipv4",
		"internal_ipv6",
		"ptp_ipv4",
		"ptp_ipv6",
	}

	out := make([]goldenCase, 0, len(names))
	for _, name := range names {
		metaPath := filepath.Join("testdata", name+".json")
		metaRaw, err := os.ReadFile(metaPath)
		if err != nil {
			t.Fatalf("reading %s: %v", metaPath, err)
		}
		var meta packetGolden
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			t.Fatalf("unmarshal %s: %v", metaPath, err)
		}
		payload, err := hex.DecodeString(meta.PayloadHex)
		if err != nil {
			t.Fatalf("decode payload for %s: %v", meta.Name, err)
		}
		srcMAC, err := net.ParseMAC(meta.SrcMAC)
		if err != nil {
			t.Fatalf("parse src MAC for %s: %v", meta.Name, err)
		}
		dstMAC, err := net.ParseMAC(meta.DstMAC)
		if err != nil {
			t.Fatalf("parse dst MAC for %s: %v", meta.Name, err)
		}
		local, err := netip.ParseAddrPort(meta.Local)
		if err != nil {
			t.Fatalf("parse local for %s: %v", meta.Name, err)
		}
		remote, err := netip.ParseAddrPort(meta.Remote)
		if err != nil {
			t.Fatalf("parse remote for %s: %v", meta.Name, err)
		}
		framePath := filepath.Join("testdata", name+".bin")
		frame, err := os.ReadFile(framePath)
		if err != nil {
			t.Fatalf("reading %s: %v", framePath, err)
		}
		out = append(out, goldenCase{
			meta:    meta,
			local:   local,
			remote:  remote,
			srcMAC:  append(net.HardwareAddr(nil), srcMAC...),
			dstMAC:  append(net.HardwareAddr(nil), dstMAC...),
			payload: payload,
			frame:   frame,
		})
	}
	return out
}

func buildLinkFrame(t *testing.T, tc goldenCase, csumOffload bool) []byte {
	t.Helper()

	switch tc.meta.LinkType {
	case "ptp":
		link := &linkPTP{
			localAddr:  &tc.local,
			remoteAddr: &tc.remote,
			txConns: []*udpConnection{
				{localMAC: append(net.HardwareAddr(nil), tc.srcMAC...)},
			},
			neighbors: staticNeighborCache(tc.remote.Addr(), macArray(tc.dstMAC)),
			is4:       tc.meta.Family == "ipv4",
		}
		p := newTestPacket(t, tc.payload)
		if !link.finishPacket(p, csumOffload) {
			t.Fatal("finishPacket returned false")
		}
		return append([]byte(nil), p.RawPacket...)
	case "internal":
		link := &linkInternal{
			localAddr: &tc.local,
			txConns: []*udpConnection{
				{localMAC: append(net.HardwareAddr(nil), tc.srcMAC...)},
			},
			neighbors: staticNeighborCache(tc.remote.Addr(), macArray(tc.dstMAC)),
			is4:       tc.meta.Family == "ipv4",
		}
		link.packHeader()
		p := newTestPacket(t, tc.payload)
		setRemoteAddr(p, tc.remote.Addr().AsSlice(), tc.remote.Port())
		if !link.finishPacket(p, csumOffload) {
			t.Fatal("finishPacket returned false")
		}
		return append([]byte(nil), p.RawPacket...)
	default:
		t.Fatalf("unknown link type %q", tc.meta.LinkType)
		return nil
	}
}

func buildWithHeadersAndChecksum(t *testing.T, tc goldenCase) []byte {
	t.Helper()

	if tc.meta.Family == "ipv4" {
		frame := make([]byte, headers.LenEth+headers.LenIPv4+headers.LenUDP+len(tc.payload))
		headers.BuildEth(frame, macArray(tc.dstMAC), macArray(tc.srcMAC), headers.EtherTypeIPv4)
		headers.BuildIPv4(frame[headers.LenEth:], tc.local.Addr().As4(), tc.remote.Addr().As4(),
			headers.LenIPv4+headers.LenUDP+len(tc.payload))
		headers.BuildUDP(frame[headers.LenEth+headers.LenIPv4:], tc.local.Port(), tc.remote.Port(),
			headers.LenUDP+len(tc.payload))
		copy(frame[headers.LenEth+headers.LenIPv4+headers.LenUDP:], tc.payload)
		return frame
	}

	frame := make([]byte, headers.LenEth+headers.LenIPv6+headers.LenUDP+len(tc.payload))
	headers.BuildEth(frame, macArray(tc.dstMAC), macArray(tc.srcMAC), headers.EtherTypeIPv6)
	headers.BuildIPv6(frame[headers.LenEth:], tc.local.Addr().As16(), tc.remote.Addr().As16(),
		headers.LenUDP+len(tc.payload))
	headers.BuildUDP(frame[headers.LenEth+headers.LenIPv6:], tc.local.Port(), tc.remote.Port(),
		headers.LenUDP+len(tc.payload))
	copy(frame[headers.LenEth+headers.LenIPv6+headers.LenUDP:], tc.payload)
	udpOff := headers.LenEth + headers.LenIPv6
	csum := checksum.UDP6(tc.local.Addr().As16(), tc.remote.Addr().As16(),
		frame[udpOff:udpOff+headers.LenUDP], frame[udpOff+headers.LenUDP:])
	binary.BigEndian.PutUint16(frame[udpOff+6:udpOff+8], csum)
	return frame
}

func staticNeighborCache(ip netip.Addr, mac [6]byte) *neighborCache {
	return &neighborCache{
		mappings: map[netip.Addr]neighbor{
			ip: {mac: &mac},
		},
	}
}

func newTestPacket(t *testing.T, payload []byte) *router.Packet {
	t.Helper()

	var pkt router.Packet
	pktv := reflect.ValueOf(&pkt).Elem()
	bufferField := pktv.FieldByName("buffer")
	bufferPtr := reflect.New(bufferField.Type().Elem())
	reflect.NewAt(bufferField.Type(), unsafe.Pointer(bufferField.UnsafeAddr())).Elem().Set(bufferPtr)

	buffer := bufferPtr.Elem().Slice(0, bufferPtr.Elem().Len()).Interface().([]byte)
	headroom := headers.LenEth + headers.LenIPv6 + headers.LenUDP + net.IPv6len + 2
	if headroom+len(payload) > len(buffer) {
		t.Fatalf("payload too large: headroom=%d payload=%d buffer=%d",
			headroom, len(payload), len(buffer))
	}

	pkt.RawPacket = buffer[headroom : headroom+len(payload)]
	copy(pkt.RawPacket, payload)
	return &pkt
}

func diffDump(t *testing.T, label string, want, got []byte) {
	t.Helper()

	t.Errorf("%s: frame mismatch", label)
	t.Logf("  want (%d bytes): %x", len(want), want)
	t.Logf("  got  (%d bytes): %x", len(got), got)
	for i := 0; i < len(want) && i < len(got); i++ {
		if want[i] != got[i] {
			t.Logf("  first diff at byte %d: want 0x%02x got 0x%02x", i, want[i], got[i])
			return
		}
	}
	if len(want) != len(got) {
		t.Logf("  length differs: want %d got %d", len(want), len(got))
	}
}

func macArray(mac net.HardwareAddr) [6]byte {
	if len(mac) != 6 {
		panic(fmt.Sprintf("invalid MAC length %d", len(mac)))
	}
	var out [6]byte
	copy(out[:], mac)
	return out
}
