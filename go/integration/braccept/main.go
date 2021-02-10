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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/gopacket/layers"

	"github.com/scionproto/scion/go/integration/braccept/cases"
	"github.com/scionproto/scion/go/integration/braccept/runner"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/slayers"
)

var (
	bfd        = flag.Bool("bfd", false, "Run BFD tests instead of the common ones")
	logConsole = flag.String("log.console", "debug", "Console logging level: debug|info|error")
	dir        = flag.String("artifacts", "", "Artifacts directory")
)

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

	artifactsDir, err := ioutil.TempDir("", "braccept_")
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

	rc, err := runner.NewRunConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Loading devices failed: %v\n", err)
		return 1
	}

	registerScionPorts()

	log.Info("BR V2 acceptance tests:")

	multi := []runner.Case{
		cases.ParentToChild(artifactsDir, hfMAC),
		cases.ParentToInternalHost(artifactsDir, hfMAC),
		cases.ParentToInternalHostMultiSegment(artifactsDir, hfMAC),
		cases.ChildToParent(artifactsDir, hfMAC),
		cases.ChildToChildXover(artifactsDir, hfMAC),
		cases.ChildToInternalHost(artifactsDir, hfMAC),
		cases.ChildToInternalHostShortcut(artifactsDir, hfMAC),
		cases.ChildToInternalParent(artifactsDir, hfMAC),
		cases.InternalHostToChild(artifactsDir, hfMAC),
		cases.InternalParentToChild(artifactsDir, hfMAC),
		cases.SCMPDestinationUnreachable(artifactsDir, hfMAC),
		cases.SCMPBadMAC(artifactsDir, hfMAC),
		cases.SCMPBadMACInternal(artifactsDir, hfMAC),
		cases.SCMPExpiredHopAfterXover(artifactsDir, hfMAC),
		cases.SCMPExpiredHopAfterXoverConsDir(artifactsDir, hfMAC),
		cases.SCMPExpiredHopAfterXoverInternal(artifactsDir, hfMAC),
		cases.SCMPExpiredHopAfterXoverInternalConsDir(artifactsDir, hfMAC),
		cases.SCMPExpiredHop(artifactsDir, hfMAC),
		cases.SCMPChildToParentXover(artifactsDir, hfMAC),
		cases.SCMPParentToChildXover(artifactsDir, hfMAC),
		cases.SCMPParentToParentXover(artifactsDir, hfMAC),
		cases.SCMPChildToParentLocalXover(artifactsDir, hfMAC),
		cases.SCMPParentToChildLocalXover(artifactsDir, hfMAC),
		cases.SCMPParentToParentLocalXover(artifactsDir, hfMAC),
		cases.SCMPInternalXover(artifactsDir, hfMAC),
		cases.SCMPUnknownHop(artifactsDir, hfMAC),
		cases.SCMPUnknownHopEgress(artifactsDir, hfMAC),
		cases.SCMPTracerouteIngress(artifactsDir, hfMAC),
		cases.SCMPTracerouteIngressConsDir(artifactsDir, hfMAC),
		cases.SCMPTracerouteEgress(artifactsDir, hfMAC),
		cases.SCMPTracerouteEgressConsDir(artifactsDir, hfMAC),
		cases.SCMPTracerouteEgressAfterXover(artifactsDir, hfMAC),
		cases.SCMPTracerouteInternal(artifactsDir, hfMAC),
		cases.SCMPBadPktLen(artifactsDir, hfMAC),
		cases.SCMPQuoteCut(artifactsDir, hfMAC),
		cases.NoSCMPReplyForSCMPError(artifactsDir, hfMAC),
		cases.IncomingOneHop(artifactsDir, hfMAC),
		cases.OutgoingOneHop(artifactsDir, hfMAC),
		cases.SVC(artifactsDir, hfMAC),
		cases.JumboPacket(artifactsDir, hfMAC),
	}

	if *bfd {
		multi = []runner.Case{
			cases.ExternalBFD(artifactsDir, hfMAC),
			cases.InternalBFD(artifactsDir, hfMAC),
		}
	}

	ret := 0
	for _, c := range multi {
		if err := c.Run(rc); err != nil {
			log.Error(fmt.Sprintf("%s\n%s", c.Name, err.Error()))
			ret++
			continue
		}
		log.Info(c.Name, "result", "expected packet was captured!")
	}
	return ret
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
