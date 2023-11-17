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
	"github.com/google/gopacket/layers"

	"github.com/google/gopacket/afpacket"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/keyconf"
)

type Case func(payload string, mac hash.Hash) (string, string, []byte)

var (
	allCases = map[string]Case{
		"br_transit": BrTransit,
	}
	logConsole = flag.String("log.console", "debug", "Console logging level: debug|info|error")
	dir        = flag.String("artifacts", "", "Artifacts directory")
	numPackets = flag.Int("num_packets", 10, "Number of packets to send")
	caseToRun  = flag.String("case", "",
		fmt.Sprintf("Which traffic case to evaluate %v",
			reflect.ValueOf(allCases).MapKeys()))
	handles = make(map[string]*afpacket.TPacket)
)

// initDevices inventories the available network interfaces, picks the ones that a case may inject
// traffic into, and associates them with a AF Packet interface.
func initDevices() error {
	devs, err := net.Interfaces()
	if err != nil {
		return serrors.WrapStr("listing network interfaces", err)
	}

	for _, dev := range devs {
		if !strings.HasPrefix(dev.Name, "veth_") || !strings.HasSuffix(dev.Name, "_host") {
			continue
		}
		handle, err := afpacket.NewTPacket(afpacket.OptInterface(dev.Name))
		if err != nil {
			return serrors.WrapStr("creating TPacket", err)
		}
		handles[dev.Name] = handle
	}

	return nil
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	flag.Parse()
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

	artifactsDir, err := os.MkdirTemp("", "brload_")
	if err != nil {
		log.Error("Cannot create tmp dir", "err", err)
		return 1
	}
	if *dir != "" {
		artifactsDir = *dir
	}
	if v := os.Getenv("TEST_ARTIFACTS_DIR"); v != "" {
		artifactsDir = v
	}
	hfMAC, err := loadKey(artifactsDir)
	if err != nil {
		log.Error("Loading keys failed", "err", err)
		return 1
	}

	err = initDevices()
	if err != nil {
		log.Error("Loading devices failed", "err", err)
		return 1
	}

	registerScionPorts()

	log.Info("BRLoad acceptance tests:")

	payloadString := "actualpayloadbytes"
	caseDevIn, caseDevOut, rawPkt := caseFunc(payloadString, hfMAC)

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
		numRcv := 0

		defer func() {
			listenerChan <- numRcv
			close(listenerChan)
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
			if string(layer.LayerContents()) == payloadString {
				// return // One is all we need. But continue and count for now.
				numRcv++
			}
		}
	}()

	// We started everything that could be started. So the best window for perf mertics
	// opens somewhere around now.
	metricsBegin := time.Now().Unix()
	for i := 0; i < *numPackets; i++ {
		if err := writePktTo.WritePacketData(rawPkt); err != nil {
			log.Error("writing input packet", "case", *caseToRun, "error", err)
			return 1
		}
	}
	metricsEnd := time.Now().Unix()
	// The test harness looks for this output.
	fmt.Printf("metricsBegin: %d metricsEnd: %d\n", metricsBegin, metricsEnd)

	time.Sleep(time.Second * time.Duration(2))

	// If our listener is still stuck there, unstick it. Closing the device doesn't cause the
	// packet channel to close (presumably a bug). Close the channel ourselves.
	close(packetChan)

	outcome := <-listenerChan
	if outcome == 0 {
		log.Error("Listener never saw a valid packet being forwarded")
		return 1
	}

	fmt.Printf("Listener results: %d\n", outcome)
	return 0
}

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
