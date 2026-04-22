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

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/checksum"
	"github.com/scionproto/scion/router/underlayproviders/afxdpudpip/internal/headers"
)

const (
	testVethA = "afxdplA0"
	testVethB = "afxdplB0"

	testIPv4Subnet = "10.10.0.1/24"
	testIPv4Target = "10.10.0.2"

	testIPv6Subnet = "fd99:10::1/64"
	testIPv6Target = "fd99:10::2"
)

var testPeerMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0xbb, 0xbb, 0x02}

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
	Name     string
	LinkType string
	Family   string
	Local    netip.AddrPort
	Remote   netip.AddrPort
	Payload  []byte
}

func main() {
	outDir := flag.String("out", defaultOutDir(), "directory for generated golden packet files")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("create output dir: %v", err)
	}

	ifIndex, cleanup, err := setupVeth()
	if err != nil {
		fatalf("setup veth: %v", err)
	}
	defer cleanup()

	sock, sockClose, err := openAFPacket(ifIndex)
	if err != nil {
		fatalf("open AF_PACKET: %v", err)
	}
	defer sockClose()

	srcMAC, err := mustMAC(testVethA)
	if err != nil {
		fatalf("read %s MAC: %v", testVethA, err)
	}

	cases := []goldenCase{
		{
			Name:     "ptp_ipv4",
			LinkType: "ptp",
			Family:   "ipv4",
			Local:    netip.MustParseAddrPort("10.10.0.1:53001"),
			Remote:   netip.MustParseAddrPort("10.10.0.2:45000"),
			Payload:  []byte("scion-afxdpudpip-ptp-ipv4-odd"),
		},
		{
			Name:     "ptp_ipv6",
			LinkType: "ptp",
			Family:   "ipv6",
			Local:    netip.MustParseAddrPort("[fd99:10::1]:53002"),
			Remote:   netip.MustParseAddrPort("[fd99:10::2]:45000"),
			Payload:  []byte("scion-afxdpudpip-ptp-ipv6"),
		},
		{
			Name:     "internal_ipv4",
			LinkType: "internal",
			Family:   "ipv4",
			Local:    netip.MustParseAddrPort("10.10.0.1:53003"),
			Remote:   netip.MustParseAddrPort("10.10.0.2:45000"),
			Payload:  []byte("scion-afxdpudpip-int-ipv4"),
		},
		{
			Name:     "internal_ipv6",
			LinkType: "internal",
			Family:   "ipv6",
			Local:    netip.MustParseAddrPort("[fd99:10::1]:53004"),
			Remote:   netip.MustParseAddrPort("[fd99:10::2]:45000"),
			Payload:  []byte("scion-afxdpudpip-int-ipv6-odd"),
		},
	}

	for _, tc := range cases {
		if err := sendUDP(tc.Local, tc.Remote, tc.Payload); err != nil {
			fatalf("%s: send UDP: %v", tc.Name, err)
		}
		captured, err := recvUDP(sock, tc.Remote.Port(), tc.Family)
		if err != nil {
			fatalf("%s: capture packet: %v", tc.Name, err)
		}
		frame, err := normalizeCapturedFrame(captured, tc)
		if err != nil {
			fatalf("%s: normalize packet: %v", tc.Name, err)
		}
		meta := packetGolden{
			Name:       tc.Name,
			LinkType:   tc.LinkType,
			Family:     tc.Family,
			Local:      tc.Local.String(),
			Remote:     tc.Remote.String(),
			SrcMAC:     srcMAC.String(),
			DstMAC:     testPeerMAC.String(),
			PayloadHex: hex.EncodeToString(tc.Payload),
		}
		if err := writeGolden(*outDir, meta, frame); err != nil {
			fatalf("%s: write golden: %v", tc.Name, err)
		}
		fmt.Printf("wrote %s\n", tc.Name)
	}
}

func defaultOutDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "testdata"
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "testdata"))
}

func writeGolden(outDir string, meta packetGolden, frame []byte) error {
	metaPath := filepath.Join(outDir, meta.Name+".json")
	framePath := filepath.Join(outDir, meta.Name+".bin")

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	metaJSON = append(metaJSON, '\n')

	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		return fmt.Errorf("write metadata %s: %w", metaPath, err)
	}
	if err := os.WriteFile(framePath, frame, 0o644); err != nil {
		return fmt.Errorf("write frame %s: %w", framePath, err)
	}
	return nil
}

func normalizeCapturedFrame(captured []byte, tc goldenCase) ([]byte, error) {
	var wantLen int
	switch tc.Family {
	case "ipv4":
		wantLen = headers.LenEth + headers.LenIPv4 + headers.LenUDP + len(tc.Payload)
	case "ipv6":
		wantLen = headers.LenEth + headers.LenIPv6 + headers.LenUDP + len(tc.Payload)
	default:
		return nil, fmt.Errorf("unknown family %q", tc.Family)
	}

	if len(captured) < wantLen {
		return nil, fmt.Errorf("captured frame too short: got %d want >= %d", len(captured), wantLen)
	}
	frame := append([]byte(nil), captured[:wantLen]...)

	if tc.Family == "ipv4" {
		frame[headers.LenEth+4] = 0
		frame[headers.LenEth+5] = 0
		frame[headers.LenEth+10] = 0
		frame[headers.LenEth+11] = 0
		binary.BigEndian.PutUint16(frame[headers.LenEth+10:headers.LenEth+12],
			checksum.IPv4Header(frame[headers.LenEth:headers.LenEth+headers.LenIPv4]))
		frame[headers.LenEth+headers.LenIPv4+6] = 0
		frame[headers.LenEth+headers.LenIPv4+7] = 0
		return frame, nil
	}

	copy(frame[headers.LenEth:headers.LenEth+4], []byte{0x60, 0x00, 0x00, 0x00})
	return frame, nil
}

func setupVeth() (peerIfIndex int, cleanup func(), err error) {
	if link, lookupErr := netlink.LinkByName(testVethA); lookupErr == nil {
		_ = netlink.LinkDel(link)
	}

	la := netlink.NewLinkAttrs()
	la.Name = testVethA
	veth := &netlink.Veth{LinkAttrs: la, PeerName: testVethB}
	if err := netlink.LinkAdd(veth); err != nil {
		return 0, nil, fmt.Errorf("LinkAdd veth: %w", err)
	}
	cleanup = func() {
		if link, lookupErr := netlink.LinkByName(testVethA); lookupErr == nil {
			_ = netlink.LinkDel(link)
		}
	}

	a, err := netlink.LinkByName(testVethA)
	if err != nil {
		cleanup()
		return 0, nil, fmt.Errorf("LinkByName %s: %w", testVethA, err)
	}
	b, err := netlink.LinkByName(testVethB)
	if err != nil {
		cleanup()
		return 0, nil, fmt.Errorf("LinkByName %s: %w", testVethB, err)
	}

	for _, l := range []netlink.Link{a, b} {
		if err := netlink.LinkSetUp(l); err != nil {
			cleanup()
			return 0, nil, fmt.Errorf("LinkSetUp %s: %w", l.Attrs().Name, err)
		}
	}
	if err := disableTxChecksumOffload(testVethA); err != nil {
		cleanup()
		return 0, nil, err
	}

	for _, cidr := range []string{testIPv4Subnet, testIPv6Subnet} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			cleanup()
			return 0, nil, fmt.Errorf("ParseAddr %s: %w", cidr, err)
		}
		if addr.IP.To4() == nil {
			addr.Flags = unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(a, addr); err != nil {
			cleanup()
			return 0, nil, fmt.Errorf("AddrAdd %s on %s: %w", cidr, testVethA, err)
		}
	}

	for _, entry := range []struct {
		ip     string
		family int
	}{
		{testIPv4Target, netlink.FAMILY_V4},
		{testIPv6Target, netlink.FAMILY_V6},
	} {
		ip := net.ParseIP(entry.ip)
		if ip == nil {
			cleanup()
			return 0, nil, fmt.Errorf("parse %s", entry.ip)
		}
		if err := netlink.NeighAdd(&netlink.Neigh{
			LinkIndex:    a.Attrs().Index,
			Family:       entry.family,
			State:        netlink.NUD_PERMANENT,
			IP:           ip,
			HardwareAddr: testPeerMAC,
		}); err != nil {
			cleanup()
			return 0, nil, fmt.Errorf("NeighAdd %s: %w", entry.ip, err)
		}
	}

	return b.Attrs().Index, cleanup, nil
}

func disableTxChecksumOffload(ifName string) error {
	cmd := exec.Command("ethtool", "-K", ifName, "tx", "off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ethtool -K %s tx off: %w (%s)", ifName, err, bytes.TrimSpace(out))
	}
	return nil
}

func openAFPacket(ifIndex int) (*os.File, func(), error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, nil, err
	}
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIndex,
	}
	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	tv := unix.Timeval{Sec: 0, Usec: 200_000}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), "af_packet")
	return f, func() { _ = f.Close() }, nil
}

func recvUDP(f *os.File, wantDstPort uint16, family string) ([]byte, error) {
	buf := make([]byte, 65536)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := syscall.Read(int(f.Fd()), buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				continue
			}
			return nil, err
		}
		if n < headers.LenEth {
			continue
		}
		frame := append([]byte(nil), buf[:n]...)
		et := binary.BigEndian.Uint16(frame[12:14])

		var udpOff int
		switch {
		case family == "ipv4" && et == headers.EtherTypeIPv4 &&
			n >= headers.LenEth+headers.LenIPv4+headers.LenUDP:
			if frame[headers.LenEth+9] != headers.IPProtoUDP {
				continue
			}
			udpOff = headers.LenEth + int(frame[headers.LenEth]&0x0F)*4
		case family == "ipv6" && et == headers.EtherTypeIPv6 &&
			n >= headers.LenEth+headers.LenIPv6+headers.LenUDP:
			if frame[headers.LenEth+6] != headers.IPProtoUDP {
				continue
			}
			udpOff = headers.LenEth + headers.LenIPv6
		default:
			continue
		}
		if udpOff+headers.LenUDP > n {
			continue
		}
		if binary.BigEndian.Uint16(frame[udpOff+2:udpOff+4]) != wantDstPort {
			continue
		}
		return frame, nil
	}
	return nil, fmt.Errorf("did not capture dst port %d within 2s", wantDstPort)
}

func sendUDP(local, remote netip.AddrPort, payload []byte) error {
	c, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(local), net.UDPAddrFromAddrPort(remote))
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(payload)
	return err
}

func mustMAC(name string) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...), nil
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
