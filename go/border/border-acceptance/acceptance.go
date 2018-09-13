package main

import (
	//"syscall"
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/kormat/fmt15"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
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
	keysDirPath     string
	devInfoFilePath string
	err             error
	devList         []*ifInfo
	devByName       map[string]*ifInfo
	masterKeys      keyconf.Master
	mac             hash.Hash
	testIdx         int
)

func init() {
	flag.StringVar(&borderID, "borderID", "", "Border Router ID")
	flag.StringVar(&devInfoFilePath, "devInfoFilePath", "", "Device information file path")
	flag.StringVar(&keysDirPath, "keysDirPath", "", "AS keys directory path")
	flag.IntVar(&testIdx, "testIndex", -1, "Run specific test")
}

func parseInfo() {
	f, err := os.Open(devInfoFilePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	devByName = make(map[string]*ifInfo)
	for scanner.Scan() {
		field := strings.Split(scanner.Text(), " ")
		fmt.Printf("%v\n", field)
		elem := &ifInfo{hostDev: field[0], contDev: field[1]}
		elem.mac, err = net.ParseMAC(field[2])
		if err != nil {
			panic(err)
		}
		devList = append(devList, elem)
		devByName[field[1]] = elem
	}
}

func genKeys() {
	// Load master keys
	masterKeys, err = keyconf.LoadMaster(keysDirPath)
	if err != nil {
		panic(err)
	}
	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(masterKeys.Key0, []byte("Derive OF Key"), 1000, 16, sha256.New)
	fmt.Printf("hfGenKey: ")
	for _, v := range hfGenKey {
		fmt.Printf("%d,", uint8(v))
	}
	fmt.Println()

	// First check for MAC creation errors.
	if mac, err = scrypto.InitMac(hfGenKey); err != nil {
		panic(err)
	}
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

func main() {
	if err := checkFlags(); err != nil {
		fmt.Printf("%s\n", err)
		flag.Usage()
		os.Exit(-1)
	}

	parseInfo()

	genKeys()

	for _, ifi := range devList {
		ifi.handle, err = pcap.OpenLive(ifi.hostDev, snapshot_len, promiscuous, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
		defer ifi.handle.Close()
	}

	// TODO Drop capabilities

	// TODO choose between different tests, ie. core/non-core

	brTests, ok := Tests[borderID]
	if !ok {
		panic(fmt.Sprintf("Wrong Border Router ID %s\n", borderID))
	}
	fmt.Printf("Acceptance tests for %s:\n", borderID)
	for i, _ := range brTests {
		curTest := brTests[i]
		if testIdx != -1 {
			curTest = brTests[testIdx]
		}
		curTest.In.genPktSent()
		//fmt.Printf("Packet:\n%v\n", *curTest.In)
		rawPkt := curTest.In.build()
		err = devByName[curTest.In.Dev].handle.WritePacketData(rawPkt)
		if err != nil {
			panic(err)
		}
		var result string
		if err := checkRecvPkts(curTest); err != nil {
			fmt.Println(err)
			result = fail()
		} else {
			result = pass()
		}
		a := curTest.In.AddrHdr
		fmt.Printf("Test %d: %s,[%s] -> %s,[%s] %s\n%s\n", i,
			a.SrcIA, a.SrcHost, a.DstIA, a.DstHost, result, printSegs(curTest.In.Path.Segs))
		if testIdx != -1 {
			break
		}
	}
}

const (
	//	defColorFmt = "\x1b[%dm%s\x1b[0m"
	passUni = "\u2714"
	failUni = "\u2715"
	green   = 32
	red     = 31
)

func pass() string {
	//	return fmt.Sprintf(defColorFmt, green, passUni)
	return fmt15.ColorStr(passUni, green)
}

func fail() string {
	//	return fmt.Sprintf(defColorFmt, red, failUni)
	return fmt15.ColorStr(failUni, red)
}

var (
	if_1A_2A = common.IFIDType(1201)
	if_1B_3A = common.IFIDType(1301)
	if_1B_4A = common.IFIDType(1401)
	if_1B_4B = common.IFIDType(1402)
	if_1C_5A = common.IFIDType(1501)
	if_2A_1A = common.IFIDType(2101)
	if_3A_1B = common.IFIDType(3101)
	if_4A_1B = common.IFIDType(4101)
	if_4B_1B = common.IFIDType(4102)
	if_5A_1C = common.IFIDType(5101)
)

/*
                Ingress-HFas-Egress
Path ConsDir ConsInress-HFas-ConsEgress
2->1 True    0-HF2-2101  <>  1201-HF1-0  - Registered path in AS-1
1->2 True    0-HF1-1201  <>  2101-HF2-0  - Registered path in AS-2

Reversed paths:
                 Egress-HFas-Ingress
Path ConsDir ConsInress-HFas-ConsEgress
1->2 False   1201-HF1-0  <>  0-HF2-2101
2->1 False   2101-HF2-0  <>  0-HF1-1201
*/

var tsNow = uint32(time.Now().Unix())
var (
	// Core paths between ff00:0:1 <-> ff00:0:2
	path_2A_1A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A}}},
	}
	path_2A_1A_rev = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1A_2A}, {ConsEgress: if_2A_1A}}},
	}
	path_1A_2A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1A_2A}, {ConsIngress: if_2A_1A}}},
	}
	path_1A_2A_rev = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_2A_1A}, {ConsEgress: if_1A_2A}}},
	}
	// Core paths between ff00:0:1 <-> ff00:0:3
	path_3A_1B = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_3A_1B}, {ConsIngress: if_1B_3A}}},
	}
	path_3A_1B_rev = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1B_3A}, {ConsEgress: if_3A_1B}}},
	}
	path_1B_3A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1B_3A}, {ConsIngress: if_3A_1B}}},
	}
	path_1B_3A_rev = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_3A_1B}, {ConsEgress: if_1B_3A}}},
	}
	// Paths between ff00:0:1 <-> ff00:0:5
	path_5A_1C = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5A_1C}, {ConsEgress: if_1C_5A}}},
	}
	path_1C_5A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1C_5A}, {ConsIngress: if_5A_1C}}},
	}
	path_2A_1A_X_1C_5A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1C_5A}, {ConsIngress: if_5A_1C}}},
	}
	path_5A_1C_X_1A_2A = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_5A_1C}, {ConsEgress: if_1C_5A, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1A_2A}, {ConsEgress: if_2A_1A}}},
	}
	// Bad paths - Xover CORE to CORE
	path_rev_2A_1A_X_1B_3A = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_3A_1B}, {ConsEgress: if_1B_3A, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1A_2A, Xover: true}, {ConsEgress: if_2A_1A}}},
	}
	path_2A_1A_X_1B_3A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1B_3A, Xover: true}, {ConsIngress: if_3A_1B}}},
	}
	path_2A_1A_X_3A_1B_rev = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1B_3A, Xover: true}, {ConsEgress: if_3A_1B}}},
	}
	path_1A_2A_rev_X_1B_3A = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_2A_1A}, {ConsEgress: if_1A_2A, Xover: true}}},
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_1B_3A, Xover: true}, {ConsIngress: if_3A_1B}}},
	}
	path_1A_2A_rev_X_3A_1B_rev = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_2A_1A}, {ConsEgress: if_1A_2A, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1B_3A, Xover: true}, {ConsEgress: if_3A_1B}}},
	} // Bad path - Xover DOWN to CORE
	path_5A_1C_X_1B_3A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsEgress: if_5A_1C}, {ConsIngress: if_1C_5A, Xover: true}}},
		{spath.InfoField{ConsDir: false, ISD: 1, TsInt: tsNow, Hops: 2},
			[]spath.HopField{{ConsIngress: if_1B_3A}, {ConsEgress: if_3A_1B}}},
	}
)

var Tests map[string][]*BRTest = map[string][]*BRTest{
	// CtrlAddr:     192.168.0.101 30087
	// InternalAddr: 192.168.0.11 30087
	// ifid_1201:    192.168.12.2 50000 -> 192.168.12.3 40000, CORE, 1-ff00:0:2
	"core-brA": []*BRTest{
		{
			In: &pktInfo{
				Dev:     "ifid_1201",
				Overlay: gOverlay("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:1", "192.168.0.51"),
				Path:    gPath(1, 2, path_2A_1A),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{
				{Dev: "ifid_local",
					Overlay: gOverlay("192.168.0.11", 30087, "192.168.0.51", 30041),
				},
			},
		},
		{
			In: &pktInfo{
				Dev:     "ifid_local",
				Overlay: gOverlay("192.168.0.51", 30041, "192.168.0.11", 30087),
				AddrHdr: NewAddrHdr("1-ff00:0:1", "192.168.0.51", "1-ff00:0:2", "172.16.2.1"),
				Path:    gPath(1, 1, path_1A_2A),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{
				{Dev: "ifid_1201",
					Overlay: gOverlay("192.168.12.2", 50000, "192.168.12.3", 40000),
					Path:    gPath(1, 2, path_1A_2A),
				},
			},
		},
		{
			In: &pktInfo{
				Dev:     "ifid_1201",
				Overlay: gOverlay("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:5", "172.16.5.1"),
				Path:    gPath(1, 2, path_2A_1A_X_1C_5A),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{
				{Dev: "ifid_local",
					Overlay: gOverlay("192.168.0.11", 30087, "192.168.0.13", 30087),
					Path:    gPath(2, 1, path_2A_1A_X_1C_5A),
				},
			},
		},
		{
			In: &pktInfo{
				Dev:     "ifid_local",
				Overlay: gOverlay("192.168.0.13", 30087, "192.168.0.11", 30087),
				AddrHdr: NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:2", "172.16.2.1"),
				Path:    gPath(2, 1, path_5A_1C_X_1A_2A),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{
				{Dev: "ifid_1201",
					Overlay: gOverlay("192.168.12.2", 50000, "192.168.12.3", 40000),
					Path:    gPath(2, 2, path_5A_1C_X_1A_2A),
				},
			},
		},
		{ // Bad path - Xover CORE to CORE
			In: &pktInfo{
				Dev:     "ifid_1201",
				Overlay: gOverlay("192.168.12.3", 40000, "192.168.12.2", 50000),
				AddrHdr: NewAddrHdr("1-ff00:0:2", "172.16.2.1", "1-ff00:0:3", "172.16.3.1"),
				Path:    gPath(1, 2, path_2A_1A_X_1B_3A),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{},
		},
	},
	// CtrlAddr:     192.168.0.103 30087
	// InternalAddr: 192.168.0.13 30087
	// ifid_1501:    192.168.15.2 50000 -> 192.168.15.3 40000, CORE, 1-ff00:0:5
	"core-brC": []*BRTest{
		{
			In: &pktInfo{
				Dev:     "ifid_1501",
				Overlay: gOverlay("192.168.15.3", 40000, "192.168.15.2", 50000),
				AddrHdr: NewAddrHdr("1-ff00:0:5", "172.16.5.1", "1-ff00:0:1", "192.168.0.51"),
				Path:    gPath(1, 2, path_5A_1C),
				L4:      &l4.UDP{40111, 40222, 8, []byte{0, 0}},
			},
			Out: []*pktInfo{
				{Dev: "ifid_local",
					Overlay: gOverlay("192.168.0.13", 30087, "192.168.0.51", 30041),
				},
			},
		},
	},
}
