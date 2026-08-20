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

package headers

import (
	"encoding/binary"
	"testing"

	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
)

func TestBuildIPv4_Fields(t *testing.T) {
	buf := make([]byte, LenIPv4)
	BuildIPv4(buf, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, LenIPv4+LenUDP+100)

	if buf[0] != 0x45 {
		t.Errorf("version/IHL: got 0x%02x want 0x45", buf[0])
	}
	if buf[1] != 0 {
		t.Errorf("DSCP/ECN: got 0x%02x want 0x00", buf[1])
	}
	if got := binary.BigEndian.Uint16(buf[2:4]); got != LenIPv4+LenUDP+100 {
		t.Errorf("total length: got %d want %d", got, LenIPv4+LenUDP+100)
	}
	if got := binary.BigEndian.Uint16(buf[6:8]); got != 0x4000 {
		t.Errorf("flags+frag: got 0x%04x want 0x4000 (DF=1)", got)
	}
	if buf[8] != defaultTTL {
		t.Errorf("TTL: got %d want %d", buf[8], defaultTTL)
	}
	if buf[9] != IPProtoUDP {
		t.Errorf("protocol: got %d want %d", buf[9], IPProtoUDP)
	}
	// Verify checksum by re-summing the header: a valid header sums to 0x0000
	// after inversion (RFC 1071).
	if got := checksum.IPv4Header(buf); got != 0 {
		t.Errorf("IPv4 header checksum does not self-verify: 0x%04x", got)
	}
}

func TestBuildIPv6_Fields(t *testing.T) {
	buf := make([]byte, LenIPv6)
	src := [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	BuildIPv6(buf, src, dst, LenUDP+100)

	if buf[0] != 0x60 {
		t.Errorf("version/TC high: got 0x%02x want 0x60", buf[0])
	}
	if got := binary.BigEndian.Uint16(buf[4:6]); got != LenUDP+100 {
		t.Errorf("payload length: got %d want %d", got, LenUDP+100)
	}
	if buf[6] != IPProtoUDP {
		t.Errorf("next header: got %d want %d", buf[6], IPProtoUDP)
	}
	if buf[7] != defaultTTL {
		t.Errorf("hop limit: got %d want %d", buf[7], defaultTTL)
	}
}

func TestBuildUDP_Fields(t *testing.T) {
	buf := make([]byte, LenUDP)
	BuildUDP(buf, 50000, 50001, LenUDP+100)
	if got := binary.BigEndian.Uint16(buf[0:2]); got != 50000 {
		t.Errorf("src port: got %d want 50000", got)
	}
	if got := binary.BigEndian.Uint16(buf[2:4]); got != 50001 {
		t.Errorf("dst port: got %d want 50001", got)
	}
	if got := binary.BigEndian.Uint16(buf[4:6]); got != LenUDP+100 {
		t.Errorf("length: got %d want %d", got, LenUDP+100)
	}
	if buf[6] != 0 || buf[7] != 0 {
		t.Errorf("checksum: got 0x%02x%02x want 0x0000 (zeroed)", buf[6], buf[7])
	}
}

func TestBuildEth_Fields(t *testing.T) {
	buf := make([]byte, LenEth)
	src := [6]byte{0x02, 0, 0, 0, 0, 0x01}
	dst := [6]byte{0x02, 0, 0, 0, 0, 0x02}
	BuildEth(buf, dst, src, EtherTypeIPv6)
	for i, want := range dst {
		if buf[i] != want {
			t.Errorf("dst MAC byte %d: got 0x%02x want 0x%02x", i, buf[i], want)
		}
	}
	for i, want := range src {
		if buf[6+i] != want {
			t.Errorf("src MAC byte %d: got 0x%02x want 0x%02x", i, buf[6+i], want)
		}
	}
	if got := binary.BigEndian.Uint16(buf[12:14]); got != EtherTypeIPv6 {
		t.Errorf("ethertype: got 0x%04x want 0x%04x", got, EtherTypeIPv6)
	}
}
