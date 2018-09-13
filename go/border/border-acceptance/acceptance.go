package main

import (
	//"syscall"
	"bufio"
	"crypto/sha256"
	"fmt"
	"hash"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/as_conf"
	"github.com/scionproto/scion/go/lib/common"
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
	confDir      string        = "go/border/border-acceptance"
	timeout      time.Duration = 3 * time.Second
)

var (
	err        error
	devList    []*ifInfo
	devByName  map[string]*ifInfo
	masterKeys *as_conf.MasterKeys
	mac        hash.Hash
)

func parseInfo() {
	f, err := os.Open(path.Join(confDir, "info.txt"))
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
	masterKeys, err = as_conf.LoadMasterKeys(path.Join(confDir, "br-core-conf/keys"))
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

func main() {
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

	// TODO loop over different tests

	curTest := Tests[0]

	pkt, expPkts := buildPkts(curTest)

	// Send packet
	rawPkt := buildOverlay(pkt.dev, pkt.overlay, pkt.data)
	err = devByName[pkt.dev].handle.WritePacketData(rawPkt)
	if err != nil {
		panic(err)
	}

	if err := checkRecvPkts(expPkts); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("Acceptance tests success!\n")
	}
	fmt.Println("Exiting")
}

var (
	if_1A_2A = common.IFIDType(1201)
	if_1B_3A = common.IFIDType(1301)
	if_1B_4A = common.IFIDType(1401)
	if_1B_5A = common.IFIDType(1501)
	if_1C_4B = common.IFIDType(1402)
	if_2A_1A = common.IFIDType(2101)
	if_3A_1B = common.IFIDType(3101)
	if_4A_1B = common.IFIDType(4101)
	if_4B_1C = common.IFIDType(4102)
	if_5A_1B = common.IFIDType(5101)
)

var (
	path_2A_1A = []*segDef{
		{spath.InfoField{ConsDir: true, ISD: 1},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A}}},
	}
	path_2A_1A_1B_5A = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1},
			[]spath.HopField{{ConsEgress: if_2A_1A}, {ConsIngress: if_1A_2A}}},
		{spath.InfoField{ConsDir: true, ISD: 1},
			[]spath.HopField{{ConsEgress: if_1B_5A}, {ConsIngress: if_5A_1B}}},
	}
	path_5A_1B_1A_2A = []*segDef{
		{spath.InfoField{ConsDir: false, ISD: 1},
			[]spath.HopField{{ConsEgress: if_5A_1B}, {ConsIngress: if_1B_5A}}},
		{spath.InfoField{ConsDir: true, ISD: 1},
			[]spath.HopField{{ConsEgress: if_1A_2A}, {ConsIngress: if_2A_1A}}},
	}
)

var Tests []*BRTest = []*BRTest{
	{
		BorderID: "core-brA",
		In: &pktInfo{"ifid_1201", &overlayInfo{"192.168.12.4", 40000, "192.168.12.3", 50000},
			1, 2, &addrInfo{"1-ff00:0:2", "1-ff00:0:1", "172.16.2.1", "192.168.0.51"}, path_2A_1A},
		Out: []*pktInfo{
			{"ifid_local", &overlayInfo{"192.168.0.11", 30087, "192.168.0.51", 30041},
				1, 2, &addrInfo{"1-ff00:0:2", "1-ff00:0:1", "172.16.2.1", "192.168.0.51"}, path_2A_1A},
		},
	},
	{
		BorderID: "core-brA",
		In: &pktInfo{"ifid_1201", &overlayInfo{"192.168.12.4", 40000, "192.168.12.3", 50000},
			1, 2, &addrInfo{"1-ff00:0:2", "1-ff00:0:5", "172.16.2.1", "172.16.5.1"}, path_2A_1A_1B_5A},
		Out: []*pktInfo{
			{"ifid_local", &overlayInfo{"192.168.0.11", 30087, "192.168.0.12", 30087},
				1, 2, &addrInfo{"1-ff00:0:2", "1-ff00:0:5", "172.16.2.1", "172.16.5.1"}, path_2A_1A_1B_5A},
		},
	},
}
