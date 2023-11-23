// Copyright 2023 SCION Association
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

package main

import (
	"flag"
	"fmt"
	"hash"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/acceptance/router_newbenchmark/cases"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/keyconf"
)

// multiple values for a string flag.
type arrayFlags []string

func (i *arrayFlags) String() string {
	return "A repeatable string argument"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}

type Case func(payload string, mac hash.Hash, numDistinct int) (string, string, [][]byte)

var (
	allCases = map[string]Case{
		"br_transit": cases.BrTransit,
	}
	logConsole = flag.String("log.console", "debug", "Console logging level: debug|info|error")
	dir        = flag.String("artifacts", "", "Artifacts directory")
	numPackets = flag.Int("num_packets", 10, "Number of packets to send")
	numStreams = flag.Int("num_streams", 4, "Number of independent streams (flow IDs) to use")
	caseToRun  = flag.String("case", "",
		fmt.Sprintf("Which traffic case to evaluate %v",
			reflect.ValueOf(allCases).MapKeys()))
	showIntf   = flag.Bool("show_interfaces", false, "Show interfaces needed by the test")
	interfaces = arrayFlags{}
)

// initDevices inventories the available network interfaces, picks the ones that a case may inject
// traffic into, and associates them with a AF Packet interface. It returns the packet interfaces
// corresponding to each network interface.
func openDevices() (map[string]*afpacket.TPacket, error) {
	devs, err := net.Interfaces()
	if err != nil {
		return nil, serrors.WrapStr("listing network interfaces", err)
	}

	handles := make(map[string]*afpacket.TPacket)

	for _, dev := range devs {
		if !strings.HasPrefix(dev.Name, "veth_") || !strings.HasSuffix(dev.Name, "_host") {
			continue
		}
		handle, err := afpacket.NewTPacket(afpacket.OptInterface(dev.Name))
		if err != nil {
			return nil, serrors.WrapStr("creating TPacket", err)
		}
		handles[dev.Name] = handle
	}

	return handles, nil
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Var(&interfaces, "interface",
		`label=host_interface,mac,peer_mac where:
    host_interface: use this to exchange traffic with interface <label>
    mac: the mac address of interface <label>
    peer_mac: the mac address of <host_interface>`)
	flag.Parse()
	if *showIntf {
		fmt.Println(cases.ListInterfaces())
		return 0
	}

	logCfg := log.Config{Console: log.ConsoleConfig{Level: *logConsole}}
	if err := log.Setup(logCfg); err != nil {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	defer log.HandlePanic()

	caseFunc, ok := allCases[*caseToRun]
	if !ok {
		log.Error("Unknown case", "case", *caseToRun)
		flag.Usage()
		return 1
	}

	artifactsDir := *dir
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

	cases.InitInterfaces(interfaces)
	handles, err := openDevices()
	if err != nil {
		log.Error("Loading devices failed", "err", err)
		return 1
	}

	registerScionPorts()

	log.Info("BRLoad acceptance tests:")

	payloadString := "actualpayloadbytes"
	caseDevIn, caseDevOut, rawPkts := caseFunc(payloadString, hfMAC, *numStreams)

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

	go func() {
		defer log.HandlePanic()
		receivePackets(packetChan, payloadString, listenerChan)
	}()

	// We started everything that could be started. So the best window for perf mertics
	// opens somewhere around now.
	metricsBegin := time.Now().Unix()
	for i := 0; i < *numPackets; i++ {
		if err := writePktTo.WritePacketData(rawPkts[i%*numStreams]); err != nil {
			log.Error("writing input packet", "case", *caseToRun, "error", err)
			return 1
		}
	}
	metricsEnd := time.Now().Unix()
	// The test harness looks for this output.
	fmt.Printf("metricsBegin: %d metricsEnd: %d\n", metricsBegin, metricsEnd)

	// Get the results from the packet listener.
	// Give it one second as in very short tests (<1M pkts) we get here before the first packet.
	outcome := 0
	timeout := time.After(1 * time.Second)
	for outcome == 0 {
		select {
		case outcome = <-listenerChan:
			if outcome == 0 {
				log.Error("Listener never saw a valid packet being forwarded")
				return 1
			}
		case <-timeout:
			// If our listener is still stuck there, unstick it. Closing the device doesn't cause the
			// packet channel to close (presumably a bug). Close the channel ourselves.
			// After this, the next loop is guaranteed an outcome.
			close(packetChan)
		}
	}

	fmt.Printf("Listener results: %d\n", outcome)
	return 0
}

// receivePkts consume some or all (at least one if it arrives) of the packets
// arriving on the given handle and checks that they contain the given payload.
// The number of consumed packets is returned via the given outcome channel.
// Currently we are content with receiving a single correct packet and we terminate after
// that.
func receivePackets(packetChan chan gopacket.Packet, payload string, outcome chan int) {
	numRcv := 0

	defer func() {
		outcome <- numRcv
		close(outcome)
	}()

	for {
		got, ok := <-packetChan
		if !ok {
			// No more packets
			log.Info("No more Packets")
			return
		}
		if err := got.ErrorLayer(); err != nil {
			log.Error("error decoding packet", "err", err)
			continue
		}
		layer := got.Layer(gopacket.LayerTypePayload)
		if layer == nil {
			log.Error("error fetching packet payload: no PayLoad")
			continue
		}
		if string(layer.LayerContents()) == payload {
			numRcv++
			return
		}
	}
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

// registerScionPorts registers the following UDP ports in gopacket such as SCION is the
// next layer. In other words, map the following ports to expect SCION as the payload.
func registerScionPorts() {
	layers.RegisterUDPPortLayerType(layers.UDPPort(30041), slayers.LayerTypeSCION)
	for i := 30000; i < 30010; i++ {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), slayers.LayerTypeSCION)
	}
	for i := 50000; i < 50010; i++ {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), slayers.LayerTypeSCION)
	}
}
