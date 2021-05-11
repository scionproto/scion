// Copyright 2020 Anapaya Systems
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

package runner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
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
		return nil, serrors.WrapStr("listing network interfaces", err)
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
			return nil, serrors.WrapStr("creating TPacket", err)
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

// ExpectPacket expects packet pkt on the device devName. It stores all received
// packets using the storer. If the received packet in the device is matching
// the expected packet and no other packet is received nil is returned.
// Otherwise details of what went wrong are returned in the error.
func (c *RunConfig) ExpectPacket(pkt ExpectedPacket, normalizeFn NormalizePacketFn) error {

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
			return serrors.WithCtx(errTimeout, "other err", errors.ToError())
		}
		got, ok := pktV.Interface().(gopacket.Packet)
		if !ok {
			errors = append(errors, serrors.New("got non gopacket.Packet",
				"type", common.TypeOf(pktV.Interface())))
			continue
		}
		pkt.Storer.storePkt(fmt.Sprintf("got-%d", i), got)
		// Packet received
		if c.deviceNames[idx] != pkt.DevName {
			errors = append(errors, serrors.New("received packet on unexpected interface",
				"pkt", i, "expected", pkt.DevName, "actual", c.deviceNames[idx], "packet", got))
			continue
		}
		if err := comparePkts(got, pkt.Pkt, normalizeFn); err != nil {
			errors = append(errors, serrors.WrapStr("received mismatching packet", err,
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

type NormalizePacketFn func(gopacket.Packet)

// Case represents a border router test case.
type Case struct {
	Name              string
	WriteTo, ReadFrom string
	Input, Want       []byte
	StoreDir          string
	IgnoreNonMatching bool
	// NormalizePacket is a function that will be called both on actual and
	// expected packet. It can modify the packet fields so that unpredictable
	// values are zeroed out and the packets match.
	NormalizePacket NormalizePacketFn
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

	if err := cfg.WritePacket(t.WriteTo, t.Input); err != nil {
		return serrors.WrapStr("writing input packet", err)
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
	err := cfg.ExpectPacket(ePkt, normalizePacket)
	if err == nil {
		return nil
	}
	if errors.Is(err, errTimeout) {
		log.Debug(t.Name, "msg", "timeout occurred")
	}
	return serrors.WrapStr("Errors were found", err,
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
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
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
