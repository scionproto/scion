package main

import (
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
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/crypto/pbkdf2"

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
	keysDirPath     string
	devInfoFilePath string
	testIdx         int
	//Tests           map[string][]*BRTest = map[string][]*BRTest{

	Tests = map[string][]*BRTest{
		"core-brA": coreBrATests,
		"core-brB": coreBrBTests,
		"core-brC": coreBrCTests,
		/* TODO
		"brA":      BrATests,
		"brB":      BrBTests,
		"brC":      BrCTests,
		"brD":      BrDTests,
		*/
	}
	devByName map[string]*ifInfo
	devList   []*ifInfo
	hashMac   hash.Hash
)

func init() {
	flag.StringVar(&borderID, "borderID", "", "Border Router ID")
	flag.StringVar(&devInfoFilePath, "devInfoFilePath", "", "Device information file path")
	flag.StringVar(&keysDirPath, "keysDirPath", "", "AS keys directory path")
	flag.IntVar(&testIdx, "testIndex", -1, "Run specific test")
}

func GenerateKeys(fn string) error {
	// Load master keys
	masterKeys, err := keyconf.LoadMaster(fn)
	if err != nil {
		return err
	}
	// Generate keys
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	hfGenKey := pbkdf2.Key(masterKeys.Key0, common.RawBytes("Derive OF Key"), 1000, 16, sha256.New)
	// First check for MAC creation errors.
	hashMac, err = scrypto.InitMac(hfGenKey)
	return err
}

func ParseDevInfo(fn string) error {
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
		devByName[field[1]] = elem
	}
	return nil
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
	if err := ParseDevInfo(devInfoFilePath); err != nil {
		fatal("%s\n", err)
	}
	if err := GenerateKeys(keysDirPath); err != nil {
		fatal("%s\n", err)
	}
	for _, ifi := range devList {
		var err error
		ifi.handle, err = pcap.OpenLive(ifi.hostDev, snapshot_len, promiscuous, pcap.BlockForever)
		if err != nil {
			fatal("%s\n", err)
		}
		defer ifi.handle.Close()
	}
	// Now that everything is set up, drop CAP_NET_ADMIN
	caps, err := capability.NewPid(0)
	if err != nil {
		fatal("Error retrieving capabilities: %s", err)
	}
	caps.Clear(capability.CAPS)
	caps.Apply(capability.CAPS)

	brTests, ok := Tests[borderID]
	if !ok {
		fatal("Wrong Border Router ID %s", borderID)
	}
	fmt.Printf("Acceptance tests for %s:\n", borderID)
	var failures int
	if testIdx != -1 {
		brTests = brTests[testIdx : testIdx+1]
	}
	for _, t := range brTests {
		if !doTest(t) {
			failures += 1
		}
	}
	os.Exit(failures)
}

// doTest just runs a test, which involved generating the packet, sending it in the specified
// interface, then comparing any packets coming from the border router against the expected
// packets from the test.
// It return true if the test was successful, ie. all expected packets and no others were received,
// otherwise it returns false.
func doTest(t *BRTest) bool {
	t.In.Setup()
	devInfo, ok := devByName[t.In.GetDev()]
	if !ok {
		fmt.Errorf("No device information for: %s", t.In.GetDev())
	}
	raw, err := t.In.Pack(devInfo.mac, hashMac)
	if err != nil {
		fatal("%s\n", err)
	}
	err = devInfo.handle.WritePacketData(raw)
	if err != nil {
		fatal("%s\n", err)
	}
	var pass bool
	if err := checkRecvPkts(t); err != nil {
		fmt.Println(err)
	} else {
		pass = true
	}
	fmt.Println(t.Summary(pass))
	return pass
}

func fatal(msg string, a ...interface{}) {
	fmt.Printf(msg+"\n", a...)
	os.Exit(1)
}
