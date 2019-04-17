// Copyright 2018 ETH Zurich
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
// See the License for the specdic language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	golayers "github.com/google/gopacket/layers"
	"github.com/syndtr/gocapability/capability"

	"github.com/scionproto/scion/go/border/braccept/layers"
	"github.com/scionproto/scion/go/border/braccept/shared"
	"github.com/scionproto/scion/go/lib/log"
)

const (
	snapshot_len   int32         = 1024
	promiscuous    bool          = true
	defaultTimeout               = "250ms"
	defaultDelay   time.Duration = 1 * time.Second
)

// Flag vars
var (
	testName    string
	keysDirPath string
)

func init() {
	flag.StringVar(&testName, "testName", "", "Test to run")
	flag.StringVar(&keysDirPath, "keysDirPath", "", "AS keys directory path")
}

var (
	failures int
	timerIdx int
	cases    []reflect.SelectCase
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	log.ConsoleLevel = "info"
	log.AddLogConsFlags()
	if err := checkFlags(); err != nil {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	if err := log.SetupFromFlags(""); err != nil {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	defer log.LogPanicAndExit()
	if err := shared.Init(keysDirPath); err != nil {
		log.Crit("", "err", err)
		return 1
	}
	// We setup the select cases in main so we can easily defer device handle close on exit
	timerIdx = len(shared.DevList)
	cases = make([]reflect.SelectCase, timerIdx+1)
	for i, di := range shared.DevList {
		var err error
		di.Handle, err = afpacket.NewTPacket(afpacket.OptInterface(di.Host.Name))
		if err != nil {
			log.Crit("", "err", err)
			return 1
		}
		packetSource := gopacket.NewPacketSource(di.Handle, golayers.LinkTypeEthernet)
		ch := packetSource.Packets()
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
		defer di.Handle.Close()
	}
	// Now that everything is set up, drop CAP_NET_ADMIN
	caps, err := capability.NewPid(0)
	if err != nil {
		log.Crit("Error retrieving capabilities", "err", err)
		return 1
	}
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)

	registerScionPorts()

	IgnorePkts()

	var failures int
	log.Info("Acceptance tests:", "testName", testName)
	switch testName {
	case "br_multi":
		failures += br_multi()
	case "br_child":
		failures += br_child()
	case "br_parent":
		failures += br_parent()
	case "br_peer":
		failures += br_peer()
	case "br_core_multi":
		failures += br_core_multi()
	case "br_core_coreIf":
		failures += br_core_coreIf()
	case "br_core_childIf":
		failures += br_core_childIf()
	default:
		log.Crit("Wrong BR acceptance test name", "testName", testName)
		return 1
	}
	return failures
}

func checkFlags() error {
	flag.Parse()
	if testName == "" {
		return fmt.Errorf("ERROR: Missing testName flag")
	}
	if keysDirPath == "" {
		return fmt.Errorf("ERROR: Missing keysDirPath flag")
	}
	return nil
}

// registerScionPorts basically register the following UDP ports in gopacket such as SCION is the
// next layer. In other words, map the following ports to expect SCION as the payload.
func registerScionPorts() {
	// Bind ports to SCION layer
	golayers.RegisterUDPPortLayerType(golayers.UDPPort(30041), layers.LayerTypeScion)
	for i := 30000; i < 30010; i += 1 {
		golayers.RegisterUDPPortLayerType(golayers.UDPPort(i), layers.LayerTypeScion)
	}
	for i := 50000; i < 50010; i += 1 {
		golayers.RegisterUDPPortLayerType(golayers.UDPPort(i), layers.LayerTypeScion)
	}
}
