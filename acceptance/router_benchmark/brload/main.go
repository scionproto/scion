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
		return errors.New("No such case")
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
		"in":          cases.In,
		"out":         cases.Out,
		"in_transit":  cases.InTransit,
		"out_transit": cases.OutTransit,
		"br_transit":  cases.BrTransit,
	}
	logConsole   string
	dir          string
	testDuration time.Duration
	packetSize   int
	numStreams   uint16
	caseToRun    caseChoice
	interfaces   []string
)

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
	runCmd.Flags().DurationVar(&testDuration, "duration", time.Second*15, "Test duration")
	runCmd.Flags().IntVar(&packetSize, "packet-size", 172, "Total size of each packet sent")
	runCmd.Flags().Uint16Var(&numStreams, "num-streams", 4,
		"Number of independent streams (flowID) to use")
	runCmd.Flags().StringVar(&logConsole, "log.console", "error",
		"Console logging level: debug|info|error|etc.")
	runCmd.Flags().StringVar(&dir, "artifacts", "", "Artifacts directory")
	runCmd.Flags().Var(&caseToRun, "case", "Case to run. "+caseToRun.Allowed())
	runCmd.Flags().StringArrayVar(&interfaces, "interface", []string{},
		`label=<host_interface>[,<MACaddr>] where <host_interface> is the host device that matches
 the <label> requirement from --show-interfaces and <MACaddr> is the local address to assume for it.
 <MACaddr> defaults to the real address assigned to the device`)
	runCmd.MarkFlagRequired("case")
	runCmd.MarkFlagRequired("interface")

	rootCmd.AddCommand(intfCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.CompletionOptions.HiddenDefaultCmd = true

	if rootCmd.Execute() != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func showInterfaces(cmd *cobra.Command) int {
	fmt.Println(cases.ListInterfaces())
	return 0
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

	go func() {
		defer log.HandlePanic()
		defer close(listenerChan)
		listenerChan <- receivePackets(packetChan, payload)
	}()

	// Because we're using IPV4 only, the UDP checksum is optional, so we are allowed to
	// just set it to zero instead of recomputing it. The IP checksum does not cover the payload, so
	// we don't need to update it.
	binary.BigEndian.PutUint16(rawPkt[40:42], 0)

	// Prepare a batch worth of packets.
	batchSize := int(8)
	allPkts := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		allPkts[i] = make([]byte, len(rawPkt))
		copy(allPkts[i], rawPkt)
	}

	// Share them with a multi-packets sender. We modify the flowIDs in-place for each batch.
	sender := newMpktSender(writePktTo)
	sender.setPkts(allPkts)

	// We started everything that could be started. So the best window for perf mertics
	// opens somewhere around now.
	begin := time.Now()
	metricsBegin := begin.Unix()

	numPkt := 0
	for time.Since(begin) < testDuration {
		// we break every 1000 batches to check the time
		for i := 0; i < 1000; i++ {
			// Rotate through flowIDs. We patch it directly into the SCION header of the packet. The
			// SCION header starts at offset 42. The flowID is the 20 least significant bits of the
			// first 32 bit field. To make our life simpler, we only use the last 16 bits (so no
			// more than 64K flows).
			for j := 0; j < batchSize; j++ {
				binary.BigEndian.PutUint16(allPkts[j][44:46], uint16(numPkt%int(numStreams)))
				numPkt++
			}

			if _, err := sender.sendAll(); err != nil {
				log.Error("writing input packet", "case", string(caseToRun), "error", err)
				return 1
			}
		}
	}

	metricsEnd := time.Now().Unix()

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
				log.Error("Listener never saw a valid packet being forwarded")
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
		handle, err := afpacket.NewTPacket(afpacket.OptInterface(intf), afpacket.OptFrameSize(4096))
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
