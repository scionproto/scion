package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

func init() {
	oldUsageF := flag.Usage
	flag.Usage = func() {
		oldUsageF()
		fmt.Fprintln(os.Stderr, "Description of available edit operations:")
		fmt.Fprintln(os.Stderr, "   bs | cs | ps")
		fmt.Fprintln(os.Stderr, "        change all svc addressses of the type to ipv4 "+
			"address <svalue> and port <ivalue>")
	}
}

var (
	fileFlag = flag.String("file", "", "topology file to edit")
	opFlag   = flag.String("op", "", "edit operation to perform (see below for possible values)")
	strFlag  = flag.String("svalue", "", "string operand for operation")
	intFlag  = flag.Int("ivalue", 0, "integer operand for operation")
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func realMain() error {
	var err error
	var topo *topology.RawTopo
	flag.Parse()
	if topo, err = loadTopology(); err != nil {
		return err
	}
	if err = editTopology(topo); err != nil {
		return err
	}
	if err = saveTopology(topo); err != nil {
		return err
	}
	return nil
}

func loadTopology() (*topology.RawTopo, error) {
	return topology.LoadRawFromFile(*fileFlag)
}

func editTopology(topo *topology.RawTopo) error {
	switch *opFlag {
	case "bs":
		editServiceAddresses(topo.BeaconService)
	case "cs":
		editServiceAddresses(topo.CertificateService)
	case "ps":
		editServiceAddresses(topo.PathService)
	default:
		return common.NewBasicError("Unknown operation", nil, "op", *opFlag)
	}
	return nil
}

func editServiceAddresses(m map[string]*topology.RawSrvInfo) {
	for k := range m {
		m[k] = buildDummyTopoAddress()
	}
}

func buildDummyTopoAddress() *topology.RawSrvInfo {
	return &topology.RawSrvInfo{
		Addrs: map[string]*topology.RawPubBindOverlay{
			"IPv4": &topology.RawPubBindOverlay{
				Public: topology.RawAddrPortOverlay{
					RawAddrPort: topology.RawAddrPort{
						Addr:   *strFlag,
						L4Port: *intFlag,
					},
				},
			},
		},
	}
}

func saveTopology(topo *topology.RawTopo) error {
	bytes, err := json.MarshalIndent(topo, "", "    ")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(*fileFlag, bytes, 0644); err != nil {
		return err
	}
	return nil
}
