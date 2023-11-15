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

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket/afpacket"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/private/keyconf"
)

type Case func(mac hash.Hash) (string, []byte)

var (
	allCases = map[string]Case{
		"br_transit": BrTransit,
	}
	logConsole = flag.String("log.console", "debug", "Console logging level: debug|info|error")
	dir        = flag.String("artifacts", "", "Artifacts directory")
	numPackets = flag.Int("num_packets", 1000, "Number of packets to send")
	caseToRun  = flag.String("case", "",
		fmt.Sprintf("Which traffic case to evaluate %v",
			reflect.ValueOf(allCases).MapKeys()))
	handles = make(map[string]*afpacket.TPacket)
)

// InitDevices inventories the available network interfaces, picks the ones that a case may inject
// traffic into, and associates them with a AF Packet interface.
func InitDevices() error {
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

	artifactsDir, err := os.MkdirTemp("", "brload_")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
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
		fmt.Fprintf(os.Stderr, "Loading keys failed: %v\n", err)
		return 1
	}

	err = InitDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Loading devices failed: %v\n", err)
		return 1
	}

	registerScionPorts()

	log.Info("BRLoad acceptance tests:")

	for caseName, caseFunc := range allCases {
		caseDev, rawPkt := caseFunc(hfMAC)

		writePktTo, ok := handles[caseDev]
		if !ok {
			log.Error("device not found", "device", caseDev)
			return 1
		}
		for i := 0; i < *numPackets; i++ {
			if err := writePktTo.WritePacketData(rawPkt); err != nil {
				log.Error("writing input packet", "case", caseName, "error", err)
				return 1
			}
		}

		// For now we don't read the packets coming out. There are other tests
		// for that. At some point we might just look at how many were dropped
		// by the interface to get an idea of how many made it that far.
	}
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
