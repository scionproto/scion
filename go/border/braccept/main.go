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
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/border/braccept/tpkt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
)

type ifInfo struct {
	hostDev string
	contDev string
	mac     net.HardwareAddr
	handle  *pcap.Handle
}

const (
	snapshot_len int32         = 1024
	promiscuous  bool          = true
	timeout      time.Duration = 500 * time.Millisecond
)

var (
	borderID        string
	devInfoFilePath string
	keysDirPath     string
	testIdx         int
)

func init() {
	flag.StringVar(&borderID, "borderID", "", "Border Router ID")
	flag.StringVar(&devInfoFilePath, "devInfoFilePath", "", "Device information file path")
	flag.StringVar(&keysDirPath, "keysDirPath", "", "AS keys directory path")
	flag.IntVar(&testIdx, "testIndex", -1, "Run specific test")
}

var (
	devByName map[string]*ifInfo
	devList   []*ifInfo
	hashMac   hash.Hash
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if err := checkFlags(); err != nil {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	if err := parseDevInfo(devInfoFilePath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	if err := generateKeys(keysDirPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	timerIdx := len(devList)
	cases := make([]reflect.SelectCase, timerIdx+1)
	for i, ifi := range devList {
		var err error
		ifi.handle, err = pcap.OpenLive(ifi.hostDev, snapshot_len, promiscuous, pcap.BlockForever)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			return 1
		}
		packetSource := gopacket.NewPacketSource(ifi.handle, ifi.handle.LinkType())
		ch := packetSource.Packets()
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ch)}
		defer ifi.handle.Close()
	}
	// Now that everything is set up, drop CAP_NET_ADMIN
	caps, err := capability.NewPid(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving capabilities: %s\n", err)
		return 1
	}
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)

	registerScionPorts()

	var brTests []*BRTest
	switch borderID {
	case "core-brA":
		brTests = genTestsCoreBrA(hashMac)
	case "core-brB":
		brTests = genTestsCoreBrB(hashMac)
	case "core-brC":
		brTests = genTestsCoreBrC(hashMac)
	default:
		fmt.Fprintf(os.Stderr, "Wrong Border Router ID %s\n", borderID)
		return 1
	}
	fmt.Printf("Acceptance tests for %s:\n", borderID)
	var failures int
	baseIdx := 1
	if testIdx != -1 {
		brTests = brTests[testIdx-1 : testIdx]
		baseIdx = testIdx
	}
	for i := range brTests {
		t := brTests[i]
		if err := doTest(t, cases); err != nil {
			fmt.Printf("%d. %s\n\n%s\n\n", baseIdx+i, t.Summary(false), err)
			failures += 1
		} else {
			fmt.Printf("%d. %s\n", baseIdx+i, t.Summary(true))
		}
	}
	return failures
}

func checkFlags() error {
	flag.Parse()
	if borderID == "" {
		return fmt.Errorf("ERROR: Missing borderID flag")
	}
	if keysDirPath == "" {
		return fmt.Errorf("ERROR: Missing keysDirPath flag")
	}
	if devInfoFilePath == "" {
		return fmt.Errorf("ERROR: Missing devInfoFilePath flag")
	}
	return nil
}

func parseDevInfo(fn string) error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	devByName = make(map[string]*ifInfo)
	for scanner.Scan() {
		field := strings.Split(scanner.Text(), " ")
		elem := &ifInfo{hostDev: field[0], contDev: field[1]}
		elem.mac, err = net.ParseMAC(field[2])
		if err != nil {
			return err
		}
		devList = append(devList, elem)
		devByName[elem.contDev] = elem
	}
	return nil
}

func generateKeys(fn string) error {
	// Load master keys
	masterKeys, err := keyconf.LoadMaster(fn)
	if err != nil {
		return err
	}
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(masterKeys.Key0, common.RawBytes("Derive OF Key"), 1000, 16, sha256.New)
	// First check for MAC creation errors.
	hashMac, err = scrypto.InitMac(hfGenKey)
	return err
}

// registerScionPorts basically register the following UDP ports in gopacket such as SCION is the
// next layer. In other words, map the following ports to expect SCION as the payload.
func registerScionPorts() {
	// Bind ports to SCION layer
	layers.RegisterUDPPortLayerType(layers.UDPPort(30041), tpkt.LayerTypeScion)
	for i := 30000; i < 30010; i += 1 {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), tpkt.LayerTypeScion)
	}
	for i := 50000; i < 50010; i += 1 {
		layers.RegisterUDPPortLayerType(layers.UDPPort(i), tpkt.LayerTypeScion)
	}
}

// doTest runs a test, which involves generating the packet, sending it in the specified
// interface, then comparing any packets coming from the border router against the expected
// packets from the test.
// It returns true if the test was successful, ie. all expected packets and no others were received,
// otherwise it returns false.
func doTest(t *BRTest, cases []reflect.SelectCase) error {
	devInfo, ok := devByName[t.In.Dev]
	if !ok {
		return fmt.Errorf("No device information for: %s\n", t.In.Dev)
	}
	raw, err := t.In.Pack(devInfo.mac)
	if err != nil {
		return err
	}
	err = devInfo.handle.WritePacketData(raw)
	if err != nil {
		return err
	}
	return checkRecvPkts(t, cases)
}

// checkRecvPkts compares packets received in any interface against the expected packets
// from the test, checking that they have been received on the expected interface.
// The logic here is to always wait for the timeout to finish receiving packets, thus we
// can check that only the expected packets were received.
func checkRecvPkts(t *BRTest, cases []reflect.SelectCase) error {
	timerIdx := len(devList)
	timerCh := time.After(timeout)
	// Add timeout channel as the last select case.
	cases[timerIdx] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(timerCh)}
	expPkts := append([]*tpkt.ExpPkt(nil), t.Out...)
	var errStr []string
	for {
		idx, pktV, ok := reflect.Select(cases)
		if !ok {
			cases[idx].Chan = reflect.ValueOf(nil)
			errStr = append(errStr, fmt.Sprintf("Unexpected interface %s/%s closed",
				devList[idx].hostDev, devList[idx].contDev))
			break
		}
		if idx == timerIdx {
			// Timeout receiving packets
			if len(expPkts) > 0 {
				errStr = append(errStr, fmt.Sprintf("Timeout receiving packets"))
			}
			break
		}
		// Packet received
		pkt := pktV.Interface().(gopacket.Packet)
		i, e := checkPkt(expPkts, idx, pkt)
		if e != nil {
			errStr = append(errStr, fmt.Sprintf("%s", e))
			continue
		}
		// Remove matched packet from expected packets
		expPkts = append(expPkts[:i], expPkts[i+1:]...)
	}
	if len(errStr) > 0 {
		return fmt.Errorf(strings.Join(errStr, "\n"))
	}
	return nil
}

// checkPkt compare a given packet against all the possible expected packets,
// It returns the index of the expected packet matched or an error with a pretty-print
// packet dump of the unmatched packet.
func checkPkt(expPkts []*tpkt.ExpPkt, devIdx int, pkt gopacket.Packet) (int, error) {
	var errStr []string
	for i := range expPkts {
		if devList[devIdx].contDev != expPkts[i].Dev {
			continue
		}
		if err := expPkts[i].Match(pkt); err != nil {
			errStr = append(errStr, fmt.Sprintf("[ERROR] %s\n", err))
			continue
		}
		// Expected packet matched!
		return i, nil
	}
	if len(expPkts) == 0 {
		errStr = append(errStr,
			fmt.Sprintf("[ERROR] Packet received when no packet was expected\n"))
	}
	if scnLayer := pkt.Layer(tpkt.LayerTypeScion); scnLayer != nil {
		// Set Raw to nil so it is not displayed on pretty printed packet format.
		// At this point, the received packet is not used anymore
		scn := scnLayer.(*tpkt.ScionLayer)
		scn.Path.Raw = nil
	}
	errStr = append(errStr, fmt.Sprintf("Unexpected packet on interface %s:\n\n%v",
		devList[devIdx].contDev, pkt))
	return -1, fmt.Errorf(strings.Join(errStr, "\n"))
}
