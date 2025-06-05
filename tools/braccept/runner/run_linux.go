// Copyright 2020 Anapaya Systems
// Copyright 2025 SCION Association
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

//go:build linux

package runner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
)

var errTimeout = serrors.New("timeout")

// RunConfig contains handles to all devices used in the acceptance test and
// should be used to read/write from devices.
type RunConfig struct {
	deviceNames []string
	handles     map[string]*afpacket.TPacket
	packetChans []reflect.SelectCase
}

// NewRunConfig creates a new run configuration. After usage Close should be
// called and the object should be GC'ed before it is safe to use again.
func NewRunConfig() (*RunConfig, error) {
	devs, err := net.Interfaces()
	if err != nil {
		return nil, serrors.Wrap("listing network interfaces", err)
	}
	var packetChans []reflect.SelectCase
	handles := make(map[string]*afpacket.TPacket)
	var deviceNames []string

	for _, dev := range devs {
		if !strings.HasPrefix(dev.Name, "veth_") || !strings.HasSuffix(dev.Name, "_host") {
			continue
		}
		handle, err := afpacket.NewTPacket(afpacket.OptInterface(dev.Name))
		if err != nil {
			return nil, serrors.Wrap("creating TPacket", err)
		}
		handles[dev.Name] = handle
		deviceNames = append(deviceNames, dev.Name)
		packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
		ch := packetSource.Packets()
		packetChans = append(packetChans, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}
	// allocate space for timer channel
	packetChans = append(packetChans, reflect.SelectCase{})

	return &RunConfig{
		deviceNames: deviceNames,
		handles:     handles,
		packetChans: packetChans,
	}, nil
}

// WritePacket writes the given packet to given device.
func (c *RunConfig) WritePacket(devName string, pkt []byte) error {
	writePktTo, ok := c.handles[devName]
	if !ok {
		return serrors.New("device not found", "device", devName)
	}
	return writePktTo.WritePacketData(pkt)
}

// ExpectedPacket fully describes a packet to be expected. To expect an empty
// packet a nil Pkt value can be used.
type ExpectedPacket struct {
	Storer            packetStorer
	DevName           string
	Timeout           time.Duration
	IgnoreNonMatching bool
	Pkt               gopacket.Packet
}

// Handles arp packets (silently - respond if we can, else just drop).
func (c *RunConfig) handleArp(
	ethHdr *layers.Ethernet,
	localIP net.IP,
	localMAC net.HardwareAddr,
	afp *afpacket.TPacket,
) {
	arpData := ethHdr.LayerPayload()
	var req layers.ARP
	if req.DecodeFromBytes(arpData, gopacket.NilDecodeFeedback) != nil {
		log.Debug("Bad ARP pkt")
		return
	}
	if req.Operation != layers.ARPRequest {
		// We don't need an arp cache we know all addresses. So, we only respond to requests.
		return
	}
	if slices.Equal(req.SourceProtAddress, net.IPv4zero) {
		// Probe. Respond if we have the target address. Since i'm not sure it's legal to
		// respond with the unspecified address as the target, use ours. Which is technically
		// the correct value anyway.
		req.SourceProtAddress = localIP // will become dstProtAddress in the response.
	}
	if !slices.Equal(req.DstProtAddress, localIP) {
		// Gratuitous req or not for us. No response.
		return
	}
	ethernet := layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       req.SourceHwAddress,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		HwAddressSize:     6,
		Protocol:          layers.EthernetTypeIPv4,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   localMAC,
		SourceProtAddress: req.DstProtAddress,
		DstHwAddress:      req.SourceHwAddress,
		DstProtAddress:    req.SourceProtAddress,
	}
	var seropts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	serBuf := gopacket.NewSerializeBuffer()
	if gopacket.SerializeLayers(serBuf, seropts, &ethernet, &arp) != nil {
		log.Debug("Could not serialize arp response")
		return
	}
	log.Debug("Response to ARP", "ip", arp.SourceProtAddress, "isat", arp.SourceHwAddress)
	_ = afp.WritePacketData(serBuf.Bytes())
}

// ExpectPacket expects packet pkt on the device devName. It stores all received
// packets using the storer. If the received packet in the device is matching
// the expected packet and no other packet is received nil is returned.
// Otherwise details of what went wrong are returned in the error.
func (c *RunConfig) ExpectPacket(
	pkt ExpectedPacket,
	normalizeFn NormalizePacketFn,
	localIP net.IP,
	localMAC net.HardwareAddr,
	handles map[string]*afpacket.TPacket,
) error {

	timerCh := time.After(pkt.Timeout)
	c.packetChans[len(c.deviceNames)] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(timerCh),
	}
	var errors serrors.List
	for i := 0; ; i++ {
		idx, pktV, ok := reflect.Select(c.packetChans)
		if !ok {
			return serrors.New("unexpected device closed", "device", c.deviceNames[idx])
		}
		if idx == len(c.packetChans)-1 {
			// No packet expected return errors if there are any.
			if pkt.Pkt == nil {
				return errors.ToError()
			}
			// Timeout receiving packets
			return serrors.Join(errTimeout, nil, "other err", errors.ToError())
		}
		got, ok := pktV.Interface().(gopacket.Packet)
		if !ok {
			errors = append(errors, serrors.New("got non gopacket.Packet",
				"type", common.TypeOf(pktV.Interface())))
			continue
		}
		// We're only configuring V4 addresses. So, only IPv4 traffic is ours.
		// Even on veth, there can be other things scooting by; such as ARP. Speaking of
		// ARP: we have to respond. Neighbor entries that the test harness shoves into the router
		// won't work: the router can also use a raw socket.
		if got.LinkLayer() == nil {
			log.Debug("No link hdr")
			continue
		}
		if got.LinkLayer().LayerType() != layers.LayerTypeEthernet {
			log.Debug("Not ethernet")
			continue
		}
		ethHdr := got.LinkLayer().(*layers.Ethernet)
		if ethHdr.EthernetType == layers.EthernetTypeARP {
			if afp := handles[c.deviceNames[idx]]; afp != nil {
				c.handleArp(ethHdr, localIP, localMAC, afp)
			} else {
				log.Debug("Cannot respond to arp: came in through unknown device")
			}
			continue
		}
		if ethHdr.EthernetType != layers.EthernetTypeIPv4 {
			log.Debug("Not IPv4")
			continue
		}
		if got.NetworkLayer() == nil {
			log.Debug("No netwk hdr")
			continue
		}
		ipHdr := got.NetworkLayer().(*layers.IPv4)
		if ipHdr.Protocol != layers.IPProtocolUDP {
			log.Debug("Not UDP")
			continue
		}
		if got.TransportLayer() == nil {
			log.Debug("No transport hdr")
			continue
		}
		udpHdr := got.TransportLayer().(*layers.UDP)
		// TODO(jiceatscion): also include the real expected port in the test case metadata?
		// We're being pretty sloppy here, but then, this is a closed veth, so there can't
		// be completely arbitrary noise either.
		if udpHdr.DstPort < 20000 || udpHdr.DstPort >= 60000 {
			// treat that as noise
			log.Debug("Not ours")
			continue
		}
		pkt.Storer.storePkt(fmt.Sprintf("got-%d", i), got)
		// Packet received
		if c.deviceNames[idx] != pkt.DevName {
			errors = append(errors, serrors.New("received packet on unexpected interface",
				"pkt", i, "expected", pkt.DevName, "actual", c.deviceNames[idx], "packet", got))
			continue
		}
		if err := got.ErrorLayer(); err != nil {
			errors = append(errors, serrors.Wrap("error decoding packet", err.Error(),
				"pkt", i))
			continue
		}
		if err := comparePkts(got, pkt.Pkt, normalizeFn); err != nil {
			errors = append(errors, serrors.Wrap("received mismatching packet", err,
				"pkt", i))
			continue
		}
		// match found
		if pkt.IgnoreNonMatching {
			return nil
		}
		return errors.ToError()
	}
}

// Close tears down the state.
func (c *RunConfig) Close() {
	for _, tp := range c.handles {
		if tp == nil {
			continue
		}
		tp.Close()
	}
	// make sure the handles are garbage collected as soon as possible so that
	// the finalizer runs.
	c.handles = nil
}

// Run executes a test case. It writes input pkt to interface `WriteTo` and
// listens for want pkt in interface `ReadFrom`. It stores all the packets
// in the artifact directory for further debug.
func (t *Case) Run(cfg *RunConfig) error {
	storer := packetStorer{
		StoreDir: t.StoreDir,
		TestName: t.Name,
	}
	inputPkt := gopacket.NewPacket(t.Input, layers.LinkTypeEthernet, gopacket.Default)
	defer storer.storePkt("input", inputPkt)
	var wantPkt gopacket.Packet
	if t.Want != nil {
		wantPkt = gopacket.NewPacket(t.Want, layers.LinkTypeEthernet, gopacket.Default)
		defer storer.storePkt("want", wantPkt)
	}

	// Retry once after a short delay: the router may need to arp resolve the destination. When that
	// happens, the router drops the trigger packet. It's a router not a transactional DB.
	var err error
	for attempts := range 2 {
		if err = cfg.WritePacket(t.WriteTo, t.Input); err != nil {
			return serrors.Wrap("writing input packet", err)
		}
		ePkt := ExpectedPacket{
			Storer:            storer,
			DevName:           t.ReadFrom,
			Timeout:           350 * time.Millisecond,
			IgnoreNonMatching: t.IgnoreNonMatching,
			Pkt:               wantPkt,
		}
		normalizePacket := t.NormalizePacket
		if normalizePacket == nil {
			normalizePacket = DefaultNormalizePacket
		}

		err = cfg.ExpectPacket(ePkt, normalizePacket, t.LocalIP, t.LocalMAC, cfg.handles)
		if err == nil {
			return nil
		}
		if errors.Is(err, errTimeout) {
			if attempts > 0 {
				log.Debug(t.Name, "msg", "timeout occurred")
			} else {
				time.Sleep(1 * time.Second)
			}
		} else {
			break
		}
	}
	return serrors.Wrap("Errors were found", err,
		"Packets are stored in", t.StoreDir)
}

type packetStorer struct {
	StoreDir string
	TestName string
}

func (s *packetStorer) storePkt(fileName string, packet gopacket.Packet) {
	if err := os.MkdirAll(s.StoreDir, os.ModePerm); err != nil {
		log.Error(s.TestName, "err", err)
		return
	}
	filename := filepath.Join(s.StoreDir, fileName+".pcap")
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Error(s.TestName, "err", err)
		return
	}
	defer func() {
		err := f.Close()
		if err != nil {
			log.Error(s.TestName, "err", err)
		}
	}()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(1024, layers.LinkTypeEthernet); err != nil {
		log.Error(s.TestName, "err", err)
		return
	}
	c := gopacket.CaptureInfo{
		Length:        len(packet.Data()),
		CaptureLength: len(packet.Data()),
	}
	if err := w.WritePacket(c, packet.Data()); err != nil {
		log.Error(s.TestName, "err", err)
		return
	}
}
