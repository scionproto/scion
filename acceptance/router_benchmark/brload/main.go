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

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/acceptance/router_benchmark/cases"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/keyconf"
)

type Case func(packetSize int, mac hash.Hash) (string, string, []byte, []byte)

type caseChoice string

func (c *caseChoice) String() string {
	return string(*c)
}

func (c *caseChoice) Set(v string) error {
	_, ok := allCases[v]
	if !ok {
		return errors.New("no such case")
	}
	*c = caseChoice(v)
	return nil
}

func (c *caseChoice) Type() string {
	return "string enum"
}

func (c *caseChoice) Allowed() string {
	return fmt.Sprintf("One of: %v", reflect.ValueOf(allCases).MapKeys())
}

var (
	allCases = map[string]Case{
		"in":           cases.In,
		"out":          cases.Out,
		"in_transit":   cases.InTransit,
		"out_transit":  cases.OutTransit,
		"br_transit":   cases.BrTransit,
		"in6":          cases.In6,
		"out6":         cases.Out6,
		"in_transit6":  cases.InTransit6,
		"out_transit6": cases.OutTransit6,
		"br_transit6":  cases.BrTransit6,
	}
	logConsole          string
	dir                 string
	testDuration        time.Duration
	numPackets          int
	packetSize          int
	numStreams          uint16
	caseToRun           caseChoice
	interfaces          []string
	internAddrOverrides []string
	publicAddrOverrides []string
	useIPv6             bool

	// AF_XDP transmit tunables.
	txQueues     int
	firstTxQueue int
	cpuOffset    int
	maxPPS       uint64
	maxMbps      uint64
	zerocopy     bool
	hugepages    bool
	numFrames    uint32
	frameSize    uint32
	txRing       uint32
	txBatchSize  uint32
)

// xdpConfig carries the tunables for the AF_XDP transmit path. It is consumed by
// [newXdpSender] (see xdp.go / xdp_stub.go).
type xdpConfig struct {
	txQueues        int    // number of TX sockets/queues; 0 = auto-detect
	firstQueue      int    // base NIC queue id to bind
	cpuOffset       int    // pin worker i to CPU cpuOffset+i (best effort)
	numStreams      uint16 // distinct SCION flow IDs
	maxPPS          uint64 // global max packet rate; 0 = unlimited
	maxMbps         uint64 // global max wire bitrate (Mbit/s); 0 = unlimited
	preferZerocopy  bool
	preferHugepages bool
	numFrames       uint32
	frameSize       uint32
	txRing          uint32
	batchSize       uint32
	maxPackets      int // stop after this many packets; <= 0 = unlimited
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "brload",
		Short: "Generates traffic into a specific router of a specific topology",
	}
	intfCmd := &cobra.Command{
		Use:   "show-interfaces",
		Short: "Provides a terse list of the interfaces that this test requires",
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(showInterfaces(cmd))
		},
	}
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Executes the test",
		Run: func(cmd *cobra.Command, args []string) {
			os.Exit(run(cmd))
		},
	}
	runCmd.Flags().DurationVar(&testDuration, "duration", time.Second*15,
		"Test duration")
	runCmd.Flags().IntVar(&numPackets, "num-packets", -1,
		"Maximum number of packets")
	runCmd.Flags().IntVar(&packetSize, "packet-size", 172,
		"Total size of each packet sent")
	runCmd.Flags().Uint16Var(&numStreams, "num-streams", 4,
		"Number of independent streams (flowID) to use")
	runCmd.Flags().StringVar(&logConsole, "log.console", "error",
		"Console logging level: debug|info|error|etc.")
	runCmd.Flags().StringVar(&dir, "artifacts", "", "Artifacts directory")
	runCmd.Flags().Var(&caseToRun, "case", "Case to run. "+caseToRun.Allowed())
	runCmd.Flags().StringArrayVar(&interfaces, "interface", []string{},
		"label=<host_interface>[,<MACaddr>] where <host_interface> is the host device "+
			"that matches the <label> requirement from --show-interfaces and "+
			"<MACaddr> is the local address to assume for it. "+
			"<MACaddr> defaults to the real address assigned to the device")
	runCmd.Flags().StringArrayVar(&internAddrOverrides, "intern-addr-override",
		[]string{},
		"<AS>_<router>=<IP addr> where <AS> is an AS number, <router> is the index of "+
			"one router of that AS, and <IP addr> is the IP address assigned to the "+
			"internal interface of that router")
	runCmd.Flags().StringArrayVar(&publicAddrOverrides, "public-addr-override",
		[]string{},
		`<localAS>_<remoteAS>=<IP addr> where <localAS> and <remoteAS> are AS numbers,
and <IP addr> is the IP address assigned on the side of localAS`)
	runCmd.Flags().BoolVar(&useIPv6, "ipv6", false, "Use IPv6 underlay addresses")
	runCmd.Flags().IntVar(&txQueues, "tx-queues", 0,
		"Number of AF_XDP TX sockets/queues (generator parallelism). 0 = auto "+
			"(min of NIC TX queues and GOMAXPROCS)")
	runCmd.Flags().IntVar(&firstTxQueue, "first-tx-queue", 0,
		"Base NIC queue id to bind AF_XDP TX sockets to")
	runCmd.Flags().IntVar(&cpuOffset, "cpu-offset", 0,
		"Pin TX worker i to CPU (cpu-offset + i); best effort")
	runCmd.Flags().Uint64Var(&maxPPS, "max-pps", 0,
		"Global max send rate in packets/s (0 = unlimited)")
	runCmd.Flags().Uint64Var(&maxMbps, "max-mbps", 0,
		"Global max send rate in Mbit/s wire rate (0 = unlimited). If both "+
			"--max-pps and --max-mbps are set, the tighter one applies")
	runCmd.Flags().BoolVar(&zerocopy, "zerocopy", true,
		"Prefer AF_XDP zero-copy mode (falls back to copy mode per queue)")
	runCmd.Flags().BoolVar(&hugepages, "hugepages", true, "Prefer hugepage-backed UMEM")
	runCmd.Flags().Uint32Var(&numFrames, "num-frames", 0,
		"UMEM frames per socket (0 = default)")
	runCmd.Flags().Uint32Var(&frameSize, "frame-size", 0,
		"UMEM frame size in bytes (0 = default)")
	runCmd.Flags().Uint32Var(&txRing, "tx-ring", 0,
		"TX descriptor ring size (0 = default)")
	runCmd.Flags().Uint32Var(&txBatchSize, "batch-size", 0,
		"TX batch size (0 = default)")
	runCmd.MarkFlagRequired("case")
	runCmd.MarkFlagRequired("interface")

	intfCmd.Flags().BoolVar(&useIPv6, "ipv6", false, "Use IPv6 underlay addresses")
	intfCmd.Flags().StringArrayVar(&internAddrOverrides, "intern-addr-override",
		[]string{},
		"<AS>_<router>=<IP addr> where <AS> is an AS number, <router> is the index of "+
			"one router of that AS, and <IP addr> is the IP address assigned to the "+
			"internal interface of that router")
	intfCmd.Flags().StringArrayVar(&publicAddrOverrides, "public-addr-override",
		[]string{},
		"<localAS>_<remoteAS>=<IP addr> where <localAS> and <remoteAS> are AS numbers, "+
			"and <IP addr> is the IP address assigned on the side of localAS")

	rootCmd.AddCommand(intfCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	if rootCmd.Execute() != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func showInterfaces(cmd *cobra.Command) int {
	// Process overrides if any, and create the interfaces map
	cases.InitIntIPoverrides(internAddrOverrides)
	cases.InitPubIPoverrides(publicAddrOverrides)
	if useIPv6 {
		cases.InitIntfMap6()
	} else {
		cases.InitIntfMap()
	}

	fmt.Println(cases.ListInterfaces())
	return 0
}

func rttCheck(
	writePktTo *afpacket.TPacket,
	packetChan chan gopacket.Packet,
	rawPkt []byte,
	payload []byte,
) (time.Duration, error) {
	// IPv4: zero the (optional) UDP checksum. IPv6: leave gopacket's computed
	// checksum in place — IPv6 mandates a non-zero UDP checksum and a kernel-socket
	// underlay (inet) drops zero-checksum datagrams. The AF_XDP sender recomputes
	// it per packet after patching the flow ID.
	if !isIPv6(rawPkt) {
		udpCsumOff := underlayOffsetsOf(rawPkt).udpCsum
		binary.BigEndian.PutUint16(rawPkt[udpCsumOff:udpCsumOff+2], 0)
	}

	// Prepare a batch of 1 packet.
	allPkts := make([][]byte, 1)
	allPkts[0] = make([]byte, len(rawPkt))
	copy(allPkts[0], rawPkt)

	// Share it with a multi-packets sender.
	sender := newMpktSender(writePktTo)
	sender.setPkts(allPkts)

	// Send and receive just one packet. Measure the interval.
	timeout := time.After(1 * time.Second)
	begin := time.Now()
	if _, err := sender.sendAll(); err != nil {
		return time.Duration(0), err
	}
	select {
	case <-packetChan:
	case <-timeout:
		return time.Duration(0), errors.New("listener never saw any packet")
	}
	return time.Since(begin), nil
}

func run(cmd *cobra.Command) int {
	logCfg := log.Config{Console: log.ConsoleConfig{Level: logConsole}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	defer log.HandlePanic()

	artifactsDir := dir
	if v := os.Getenv("TEST_ARTIFACTS_DIR"); v != "" {
		artifactsDir = v
	}

	if artifactsDir == "" {
		log.Error("Artifacts directory not configured")
		return 1
	}

	hfMAC, err := loadKey(artifactsDir)
	if err != nil {
		log.Error("Loading keys failed", "err", err)
		return 1
	}

	// Process overrides if any, and create the interfaces map
	cases.InitIntIPoverrides(internAddrOverrides)
	cases.InitPubIPoverrides(publicAddrOverrides)
	if useIPv6 {
		cases.InitIntfMap6()
	} else {
		cases.InitIntfMap()
	}

	interfaceNames := cases.InitInterfaces(interfaces)
	handles, err := openDevices(interfaceNames)
	if err != nil {
		log.Error("Loading devices failed", "err", err)
		return 1
	}

	registerScionPorts()

	log.Info("BRLoad acceptance tests:")
	caseFunc := allCases[string(caseToRun)] // key already checked.
	caseDevIn, caseDevOut, payload, rawPkt := caseFunc(packetSize, hfMAC)

	writePktTo, ok := handles[caseDevIn]
	if !ok {
		log.Error("device not found", "device", caseDevIn)
		return 1
	}

	readPktFrom, ok := handles[caseDevOut]
	if !ok {
		log.Error("device not found", "device", caseDevOut)
		return 1
	}

	// Try and pick-up one packet and check the payload. If that works, we're content
	// that this test works.
	packetSource := gopacket.NewPacketSource(readPktFrom, layers.LinkTypeEthernet)
	packetChan := packetSource.Packets()
	listenerChan := make(chan int)

	// IPv4: zero the (optional) UDP checksum. IPv6 keeps a valid checksum (see
	// rttCheck) because a kernel-socket underlay drops zero-checksum datagrams.
	if !isIPv6(rawPkt) {
		udpCsumOff := underlayOffsetsOf(rawPkt).udpCsum
		binary.BigEndian.PutUint16(rawPkt[udpCsumOff:udpCsumOff+2], 0)
	}

	// Measure the rtt with one packet.
	rtt, err := rttCheck(writePktTo, packetChan, rawPkt, payload)
	if err == nil {
		fmt.Printf("rtt: %s\n", rtt.String())
	} else {
		fmt.Printf("rtt error: %s\n", err)
	}

	go func() {
		defer log.HandlePanic()
		defer close(listenerChan)
		listenerChan <- receivePackets(packetChan, payload)
	}()

	// Build the AF_XDP transmit sender on the injection interface. TX fans out
	// across multiple queues/cores so no single generator core bottlenecks it;
	// the rttCheck above and the listener below stay on afpacket. Each stream
	// uses a distinct SCION flow ID.
	sender, err := newXdpSender(caseDevIn, rawPkt, xdpConfig{
		txQueues:        txQueues,
		firstQueue:      firstTxQueue,
		cpuOffset:       cpuOffset,
		numStreams:      numStreams,
		maxPPS:          maxPPS,
		maxMbps:         maxMbps,
		preferZerocopy:  zerocopy,
		preferHugepages: hugepages,
		numFrames:       numFrames,
		frameSize:       frameSize,
		txRing:          txRing,
		batchSize:       txBatchSize,
		maxPackets:      numPackets,
	})
	if err != nil {
		log.Error("Creating AF_XDP sender failed", "err", err)
		return 1
	}
	defer sender.close()

	// We started everything that could be started. So the best window for perf metrics
	// opens somewhere around now.
	metricsBegin := time.Now().Unix()

	sender.start()
	sender.wait(testDuration)

	metricsEnd := time.Now().Unix()
	log.Info("Transmit complete", "packets", sender.sent())

	// The test harness looks for this output. [metricsBegin, metricsEnd] needs to be fully
	// contained in the period when we were actually transmitting, but can be a bit smaller.
	fmt.Printf("metricsBegin: %d metricsEnd: %d\n", metricsBegin, metricsEnd)

	// Get the results from the packet listener.
	// Give it one second as in very short tests (<1M pkts) we get here before the first packet.
	outcome := 0
	timeout := time.After(1 * time.Second)
	for outcome == 0 {
		select {
		case outcome = <-listenerChan:
			if outcome == 0 {
				log.Error("listener never saw a valid packet being forwarded")
				return 1
			}
		case <-timeout:
			// If our listener is still stuck there, unstick it. Closing the device doesn't cause
			// the packet channel to close (presumably a bug). Close the channel ourselves. After
			// this, the next loop is guaranteed an outcome.
			close(packetChan)
		}
	}

	fmt.Printf("Listener results: %d\n", outcome)
	return 0
}

// receivePkts consume some or all (at least one if it arrives) of the packets
// arriving on the given handle and checks that they contain the given payload.
// The number of consumed packets is returned.
// Currently we are content with receiving a single correct packet and we terminate after
// that.
func receivePackets(packetChan chan gopacket.Packet, payload []byte) int {
	numRcv := 0

	for {
		got, ok := <-packetChan
		if !ok {
			// No more packets
			log.Info("No more Packets")
			return numRcv
		}
		if err := got.ErrorLayer(); err != nil {
			// This isn't an error. There is all sort of traffic that we might not know about
			// and not be able to read.
			// log.Error("error decoding packet", "err", err)
			continue
		}
		layer := got.Layer(gopacket.LayerTypePayload)
		if layer == nil {
			// Don't treat this as an error. This could be random traffic we don't know about.
			continue
		}
		if bytes.Equal(layer.LayerContents(), payload) {
			// That's ours.
			// To return the count of all packets received, just remove the "return" below.
			// Return will occur once packetChan closes (which happens after a short timeout at
			// the end of the test).
			numRcv++
			return numRcv
		}
	}
}

// initDevices associates each network interfaces into which a case may inject traffic with a AF
// Packet interface. It returns the packet interfaces corresponding to each network interface.
func openDevices(interfaceNames []string) (map[string]*afpacket.TPacket, error) {
	handles := make(map[string]*afpacket.TPacket)

	for _, intf := range interfaceNames {
		handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(intf),
			afpacket.OptBlockTimeout(time.Millisecond), // TPv3 waits for and aggregates packets!
			// afpacket.OptFrameSize(intf.MTU), // Constrained. default is probably best
		)
		if err != nil {
			return nil, serrors.Wrap("creating TPacket", err)
		}
		handles[intf] = handle
	}

	return handles, nil
}

// loadKey loads the keys that the router under test uses to sign hop fields.
func loadKey(artifactsDir string) (hash.Hash, error) {
	keysDir := filepath.Join(artifactsDir, "conf", "keys")
	mk, err := keyconf.LoadMaster(keysDir)
	if err != nil {
		return nil, err
	}
	macGen, err := scrypto.HFMacFactory(mk.Key0)
	if err != nil {
		return nil, err
	}
	return macGen(), nil
}

// underlayOffsets holds the byte offsets, within a raw Ethernet+IP+UDP+SCION
// frame, of the fields brload reads or rewrites. They depend only on the IP
// version, which is fixed for a whole run, so they are computed once (see
// underlayOffsetsOf) rather than re-detected per field or per packet.
//
// SCION common header layout (Version|TrafficClass|FlowID = 4|8|20 bits):
// https://scionassociation.github.io/scion-dp_I-D/draft-dekater-scion-dataplane.html#name-common-header
type underlayOffsets struct {
	udpCsum int // outer UDP checksum
	flowID  int // low 16 bits of the 20-bit SCION FlowID (bytes 2-3; common header)
}

// isIPv6 reports whether the frame's EtherType is IPv6.
func isIPv6(pkt []byte) bool {
	return binary.BigEndian.Uint16(pkt[12:14]) == 0x86DD
}

// underlayOffsetsOf detects IPv4 vs IPv6 via the EtherType and derives every
// offset from the Ethernet+IP header length.
func underlayOffsetsOf(pkt []byte) underlayOffsets {
	base := 14 + 20 // IPv4: Ethernet + IPv4 header
	if isIPv6(pkt) {
		base = 14 + 40 // IPv6: Ethernet + IPv6 header
	}
	return underlayOffsets{
		udpCsum: base + 6,  // UDP checksum
		flowID:  base + 10, // UDP header (8) + 2 into the SCION common header
	}
}

// registerScionPorts registers the following UDP ports in gopacket such as SCION is the
// next layer. In other words, map the following ports to expect SCION as the payload.
func registerScionPorts() {
	for i := 30041; i < 30043; i++ {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), slayers.LayerTypeSCION)
	}
	for i := 30000; i < 30010; i++ {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), slayers.LayerTypeSCION)
	}
	for i := 50000; i < 50010; i++ {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), slayers.LayerTypeSCION)
	}
}
