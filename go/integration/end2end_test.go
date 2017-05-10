// Copyright 2017 ETH Zurich
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

package integration

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/l4"
	"github.com/netsec-ethz/scion/go/lib/libscion"
	"github.com/netsec-ethz/scion/go/lib/sciond"
	"github.com/netsec-ethz/scion/go/lib/sock/reliable"
	"github.com/netsec-ethz/scion/go/lib/spath"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"gopkg.in/yaml.v2"
)

const DispPath = "/run/shm/dispatcher/default.sock"

// RawPayload implements interface common.Payload for byte slices
type RawPayload common.RawBytes

func (pld RawPayload) String() string {
	return common.RawBytes(pld).String()
}

func (pld RawPayload) Len() int {
	return len(pld)
}

func (pld RawPayload) Copy() (common.Payload, *common.Error) {
	newPld := make(RawPayload, pld.Len())
	copy(newPld, pld)

	return newPld, nil
}

func (pld RawPayload) Write(b common.RawBytes) (int, *common.Error) {
	return copy(pld, b), nil
}

func InitIndices(fwdPath common.RawBytes) (infoIdx, hopIdx uint8, err error) {
	infoIdx, hopIdx = 0, 1

	info, ierr := spath.InfoFFromRaw(fwdPath[infoIdx*8 : infoIdx*8+8])
	if ierr != nil {
		return 0, 0, ierr
	}
	maxHopIdx := info.Hops

	hop, ierr := spath.HopFFromRaw(fwdPath[hopIdx*8 : hopIdx*8+8])
	if ierr != nil {
		return 0, 0, ierr
	}

	if info.Up && hop.Xover {
		hopIdx += 1
		if hopIdx > maxHopIdx {
			return 0, 0, common.NewError("Skipped entire path segment", "hopIdx", hopIdx,
				"maxHopIdx", maxHopIdx)
		}
	}

	for {
		hop, ierr = spath.HopFFromRaw(fwdPath[hopIdx*8 : hopIdx*8+8])
		if ierr != nil {
			return 0, 0, ierr
		}

		if hop.VerifyOnly {
			hopIdx += 1
			if hopIdx > maxHopIdx {
				return 0, 0, common.NewError("Skipped entire path segment", "hopIdx", hopIdx,
					"maxHopIdx", maxHopIdx)
			}
		} else {
			break
		}
	}

	return infoIdx, hopIdx, nil
}

// Generates SCION Version 0 packets
func CreateUDPPacket(srcIA *addr.ISD_AS, srcLocal addr.HostAddr, dstIA *addr.ISD_AS,
	dstLocal addr.HostAddr, fwdPath common.RawBytes, data common.RawBytes,
	srcPort uint16, dstPort uint16) (common.RawBytes, error) {
	// SCION Version 0 common headers are 8-byte long
	commonHeaderSize := 8
	commonHeader := make([]byte, commonHeaderSize)
	commonHeader[0] |= (uint8(dstLocal.Type()) >> 2) << 4
	commonHeader[1] |= uint8(dstLocal.Type()) << 6
	commonHeader[1] |= uint8(srcLocal.Type())

	addrHeaderSize := dstLocal.Size() + srcLocal.Size() + dstIA.SizeOf() + srcIA.SizeOf()
	addrHeader := make([]byte, addrHeaderSize)
	// Pad to multiple of LineLen, 40 is max address header as defined by SCION specification
	if addrHeaderSize > 40 {
		return nil, common.NewError("Invalid address header size", "size", addrHeaderSize)
	}
	addrHeaderSize += (40 - addrHeaderSize) % 8

	// We do not include the L4 header size in the total header size
	totalHeaderSize := commonHeaderSize + addrHeaderSize + len(fwdPath)
	totalPacketSize := totalHeaderSize + l4.UDPLen + len(data)

	binary.BigEndian.PutUint16(commonHeader[2:4], uint16(totalPacketSize))
	commonHeader[4] = uint8(totalHeaderSize)

	// Create the packet using initial IF/HF pointers
	_, hopIdx, err := InitIndices(fwdPath)
	if err != nil {
		return nil, err
	}

	commonHeader[5] = uint8(addrHeaderSize + commonHeaderSize)
	commonHeader[6] = uint8(addrHeaderSize+commonHeaderSize) + (hopIdx * 8)

	commonHeader[7] = uint8(common.L4UDP)

	// Pack the address header
	offset := 0
	dstIA.Write(addrHeader[offset : offset+dstIA.SizeOf()])
	offset += dstIA.SizeOf()
	srcIA.Write(addrHeader[offset : offset+srcIA.SizeOf()])
	offset += srcIA.SizeOf()
	copy(addrHeader[offset:offset+dstLocal.Size()], dstLocal.Pack())
	offset += dstLocal.Size()
	copy(addrHeader[offset:offset+srcLocal.Size()], srcLocal.Pack())
	// And the padding, if it exists, contains leftover zeroes

	// Pack the L4 header
	// TODO(scrye): Might want to refactor L4 stuff out of lib/common?
	udpHeader := make([]byte, l4.UDPLen)

	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(len(data))+l4.UDPLen)

	// Compute the checksum for SCION L4
	// NOTE(scrye): is the checksum supposed to be this way? it breaks stack encap/decap
	// principles (encapsulated UDP protocol looks at bytes from upper layer SCION protocol)
	binary.BigEndian.PutUint16(udpHeader[6:8], libscion.Checksum(addrHeader[0:16],
		commonHeader[7:8], udpHeader, data))

	packet := make([]byte, 0)
	packet = append(packet, commonHeader...)
	packet = append(packet, addrHeader...)
	packet = append(packet, fwdPath...)
	packet = append(packet, udpHeader...)
	packet = append(packet, data...)

	return packet, nil
}

// ScnPktFromRaw parses an in-memory raw packet, useful when SCION packets are transported
// via a lower-layer framing protocol (e.g., ReliableSocket)
func ScnPktFromRaw(buf common.RawBytes) (*spkt.ScnPkt, error) {
	offset := uint16(0)
	scnPkt := new(spkt.ScnPkt)
	// TODO(scrye): err is defined here to avoid nil interface issues
	var err *common.Error

	scnPkt.CmnHdr, err = spkt.CmnHdrFromRaw(buf[:8])
	if err != nil {
		return nil, err
	}
	offset += 8

	scnPkt.DstIA = addr.IAFromRaw(buf[offset : offset+addr.IABytes])
	offset += addr.IABytes

	scnPkt.SrcIA = addr.IAFromRaw(buf[offset : offset+addr.IABytes])
	offset += addr.IABytes

	scnPkt.DstHost, err = addr.HostFromRaw(buf[offset:], scnPkt.CmnHdr.DstType)
	if err != nil {
		return nil, err
	}
	dstLen, err := addr.HostLen(scnPkt.CmnHdr.DstType)
	if err != nil {
		return nil, err
	}
	offset += uint16(dstLen)

	scnPkt.SrcHost, err = addr.HostFromRaw(buf[offset:], scnPkt.CmnHdr.SrcType)
	if err != nil {
		return nil, err
	}
	srcLen, err := addr.HostLen(scnPkt.CmnHdr.SrcType)
	if err != nil {
		return nil, err
	}
	offset += uint16(srcLen)

	// Skip padding, NB: SCION states addr.HostLenIPv6 is largest accepted address size
	if dstLen > addr.HostLenIPv6 {
		return nil, common.NewError("Address too large", "dstLen", dstLen)
	}
	if srcLen > addr.HostLenIPv6 {
		return nil, common.NewError("Address too large", "srcLen", srcLen)
	}
	addrPadLen := uint8((2*addr.HostLenIPv6 - dstLen - srcLen) % 8)
	offset += uint16(addrPadLen)

	addrHeaderLen := addrPadLen + srcLen + dstLen + 2*addr.IABytes

	// Compute forwarding path length, lengths are in the last byte of the 8-byte InfoField
	//pathLength := uint16(0)
	pathLength := uint16(scnPkt.CmnHdr.HdrLen) - uint16(spkt.CmnHdrLen) - uint16(addrHeaderLen)
	offset += pathLength

	scnPkt.Path = new(spath.Path)
	scnPkt.Path.Raw = make(common.RawBytes, pathLength)
	copy(scnPkt.Path.Raw, buf[offset-pathLength:offset])
	scnPkt.Path.InfOff = scnPkt.CmnHdr.CurrInfoF
	scnPkt.Path.HopOff = scnPkt.CmnHdr.CurrHopF

	// Jump directly after header
	// NOTE(?): x8 lengths are suggested in the specification, but are not implemented in
	// existing code.
	offset = uint16(scnPkt.CmnHdr.HdrLen)

	// Only unpack UDP for now
	if scnPkt.CmnHdr.NextHdr != common.L4UDP {
		return nil, common.NewError("Unsupported L4 protocol", "proto", scnPkt.CmnHdr.NextHdr)
	}
	scnPkt.L4, err = l4.UDPFromRaw(buf[offset : offset+l4.UDPLen])
	if err != nil {
		return nil, err
	}
	offset += l4.UDPLen

	// Make a pristine copy of the payload field, in case applications toy around with it
	// TODO(scrye): validate buffer length
	payloadLength := scnPkt.CmnHdr.TotalLen - uint16(scnPkt.CmnHdr.HdrLen) - l4.UDPLen
	scnPkt.Pld = make(RawPayload, payloadLength)

	_, err = scnPkt.Pld.Write(buf[offset:])
	if err != nil {
		return nil, err
	}

	return scnPkt, nil
}

func Client(tc TestCase, t *testing.T) {
	time.Sleep(100 * time.Millisecond)

	// Value and error channels for client goroutine
	v, e := make(chan string, 1), make(chan error, 1)

	go func() {
		// Test AS request/reply functionality before entering the sending loop
		sciond, err := sciond.Connect(fmt.Sprintf("/run/shm/sciond/sd%s.sock", tc.srcIA.String()))
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer sciond.Close()

		// Ask SCIOND for the forwarding path
		pathReply, err := sciond.Paths(tc.srcIA, tc.dstIA, 5, false, false)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if pathReply.ErrorCode != 0 {
			t.Fatalf("Path error: %s", pathReply.ErrorCode)
		}

		// If no path, finish test successfully
		if len(pathReply.Entries[0].Path.FwdPath) == 0 {
			return
		}

		// Choose the first path
		fwdPath := pathReply.Entries[0].Path.FwdPath
		firstHop := pathReply.Entries[0].HostInfo

		// Register with dispatcher
		regAddr := reliable.AppAddr{Addr: tc.srcLocal, Port: tc.srcPort}
		dispatcher, err := reliable.Register(DispPath, tc.srcIA, regAddr)
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer dispatcher.Close()

		// Create packet
		packet, err := CreateUDPPacket(tc.srcIA, tc.srcLocal, tc.dstIA, tc.dstLocal, fwdPath,
			tc.request, tc.srcPort, tc.dstPort)

		if err != nil {
			t.Fatalf("%v", err)
		}

		// Send payload
		a, _ := addr.HostFromRaw(firstHop.Addrs.Ipv4, addr.HostTypeIPv4)
		_, err = dispatcher.WriteTo(packet, reliable.AppAddr{Addr: a, Port: firstHop.Port})
		if err != nil {
			t.Fatalf("%v", err)
		}

		message := make([]byte, 256)

		_, _, err = dispatcher.ReadFrom(message)
		if err != nil {
			e <- common.NewError("err", err)
		}

		scnPkt, err := ScnPktFromRaw(message)
		if err != nil {
			e <- err
		}

		// Send received message to parent
		s := string([]byte(scnPkt.Pld.(RawPayload)))
		v <- s

	}()

	var message string

	select {
	case message = <-v:
	case err := <-e:
		t.Fatalf("Error %v", err)
	case <-time.After(time.Second * 3):
		t.Fatalf("Timed out waiting for message.")
	}

	if message != string(tc.reply) {
		t.Fatalf("Received message %v, expected %v", message, string(tc.request))
	}
}

func Server(tc TestCase, t *testing.T) {
	// Value and error channels for client goroutine
	v, e := make(chan string, 1), make(chan error, 1)

	// Launch communication part of server as separate goroutine
	go func() {
		// Register with dispatcher
		regAddr := reliable.AppAddr{Addr: tc.dstLocal, Port: tc.dstPort}
		dispatcher, err := reliable.Register(DispPath, tc.dstIA, regAddr)
		if err != nil {
			e <- err
			return
		}
		defer dispatcher.Close()

		message := make([]byte, 256)
		_, br, err := dispatcher.ReadFrom(message)
		if err != nil {
			e <- common.NewError("Unable to read from dispatcher", "err", err)
			return
		}

		scnPkt, err := ScnPktFromRaw(message)
		if err != nil {
			e <- err
			return
		}

		s := string([]byte(scnPkt.Pld.(RawPayload)))
		v <- s

		// TODO(scrye): ierr is used to avoid nil stored in interface
		ierr := scnPkt.Reverse()
		if ierr != nil {
			e <- err
			return
		}

		udpHeader, ok := scnPkt.L4.(*l4.UDP)
		if ok == false {
			e <- common.NewError("Type assertion scnPkt.L4.(*l4.UDP) failed")
			return
		}

		packet, err := CreateUDPPacket(scnPkt.SrcIA, scnPkt.SrcHost, scnPkt.DstIA,
			scnPkt.DstHost, []byte(scnPkt.Path.Raw), tc.reply, udpHeader.SrcPort, udpHeader.DstPort)
		if err != nil {
			e <- err
			return
		}

		_, err = dispatcher.WriteTo(packet, br)
		if err != nil {
			e <- err
			return
		}

		e <- nil
	}()

	var message string

	select {
	case err := <-e:
		if err != nil {
			t.Fatalf("Error %v", err)
		}
	case <-time.After(time.Second * 3):
		t.Fatalf("Timed out waiting for message")
	}

	message = <-v

	if message != string(tc.request) {
		t.Fatalf("Message mismatch. Expected %v, actual %v", string(tc.request), message)
	}

}

type TestCase struct {
	srcIA *addr.ISD_AS
	dstIA *addr.ISD_AS

	srcLocal addr.HostAddr
	dstLocal addr.HostAddr

	srcPort uint16
	dstPort uint16

	request []byte
	reply   []byte
}

func generateTests(clients []*addr.ISD_AS, servers []*addr.ISD_AS, count int) []TestCase {
	tests := make([]TestCase, 0, 0)
	var cIndex, sIndex int32

	for i := 0; i < count; i++ {
		for {
			cIndex = rand.Int31n(int32(len(clients)))
			sIndex = rand.Int31n(int32(len(servers)))
			if cIndex != sIndex {
				break
			}
		}

		tc := TestCase{srcIA: clients[cIndex], dstIA: servers[sIndex],
			srcPort: uint16(40000 + 2*i), dstPort: uint16(40001 + 2*i)}
		tests = append(tests, tc)
	}

	return tests
}

type ASList struct {
	Core    []string `yaml:"Core"`
	NonCore []string `yaml:"Non-core"`
}

func loadASList(t *testing.T) []*addr.ISD_AS {
	f, err := os.Open("../../gen/as_list.yml")
	if err != nil {
		t.Fatalf("%v", err)
	}

	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var aslist ASList
	yaml.Unmarshal(b, &aslist)

	asList := make([]*addr.ISD_AS, 0)
	for _, asString := range aslist.Core {
		as, err := addr.IAFromString(asString)
		if err != nil {
			t.Fatalf("Could not parse as name %v.", asString)
		}

		asList = append(asList, as)
	}

	for _, asString := range aslist.NonCore {
		as, err := addr.IAFromString(asString)
		if err != nil {
			t.Fatalf("Could not parse as name %v.", asString)
		}

		asList = append(asList, as)
	}

	return asList
}

func ClientServer(tc TestCase, t *testing.T) {
	tc.srcLocal = addr.HostFromIP(net.IPv4(127, 0, 0, 1))
	tc.dstLocal = addr.HostFromIP(net.IPv4(127, 0, 0, 1))

	tc.request = []byte("ping!")
	tc.reply = []byte("pong!")

	t.Logf("(%v,%v,%v):%v <-> (%v,%v,%v):%v", tc.srcIA.I, tc.srcIA.A, tc.srcLocal, tc.srcPort,
		tc.dstIA.I, tc.dstIA.A, tc.dstLocal, tc.dstPort)
	t.Run(fmt.Sprintf("server"), func(t *testing.T) {
		t.Parallel()
		Server(tc, t)
	})

	t.Run(fmt.Sprintf("client"), func(t *testing.T) {
		t.Parallel()
		Client(tc, t)
	})
}

func TestE2E(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	asSrcList := loadASList(t)
	asDstList := loadASList(t)

	// Generate random pairs of sources and destinations
	testCases := generateTests(asSrcList, asDstList, 10)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v->%v", tc.srcIA, tc.dstIA), func(t *testing.T) {
			ClientServer(tc, t)
		})
	}
}
