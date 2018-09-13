// +build ignore

package main

import (
	//"syscall"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	//"github.com/docker/docker/api/types"
	//"github.com/docker/docker/client"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

var (
	dstAddr      string = "192.168.0.11"
	dstPort      uint16 = 30087
	device       string = "brlocal"
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 5 * time.Second
	handle       *pcap.Handle
)

// ConnectTun creates (or opens) interface name, and then sets its state to up
func ConnectTun(name string) (rl netlink.Link, rt io.ReadWriteCloser) {
	tun, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name},
	})
	if err != nil {
		panic(err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		panic(fmt.Errorf("Unable to find new TUN device", err, "name", name))
	}
	fmt.Printf("%s Attributes:\n", link.Attrs())
	tunAddr, err := netlink.ParseAddr(dstAddr + "/24")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Set interface %s address = %s\n", link.Attrs().Name, tunAddr)
	if err := netlink.AddrReplace(link, tunAddr); err != nil {
		panic(err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		panic(fmt.Errorf("Unable to set new TUN device Up", err, "name", name))
	}
	/*
		err = netlink.SetPromiscOn(link)
		if err != nil {
			panic(fmt.Errorf("Unable to set promiscuous on", err, "name", name)
		}
	*/
	return link, tun
}

// ConnectTun creates (or opens) interface name, and then sets its state to up
func ConnectTun22222(name string) (rl netlink.Link, rt io.ReadWriteCloser, rerr error) {
	tun, err := water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: name},
	})
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if rerr != nil {
			tun.Close()
		}
	}()
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to find new TUN device", err, "name", name)
	}
	defer func() {
		if rerr != nil {
			netlink.LinkDel(link)
		}
	}()
	fmt.Printf("%s Attributes:\n", link.Attrs())
	tunAddr, err := netlink.ParseAddr(dstAddr + "/24")
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("Set interface %s address = %s\n", link.Attrs().Name, tunAddr)
	if err := netlink.AddrReplace(link, tunAddr); err != nil {
		return nil, nil, err
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to set new TUN device Up", err, "name", name)
	}
	/*
		err = netlink.SetPromiscOn(link)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to set promiscuous on", err, "name", name)
		}
	*/
	return link, tun, nil
}

func arpReq(link netlink.Link, addr, dstAddr net.IP) []byte {
	// Set up all the layers' fields we can.
	hwAddr := link.Attrs().HardwareAddr
	eth := layers.Ethernet{
		SrcMAC:       hwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(hwAddr),
		SourceProtAddress: []byte(addr),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstAddr.To4()),
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func unsolicitedArp(link netlink.Link, addr, dstAddr net.IP) []byte {
	// Set up all the layers' fields we can.
	hwAddr := link.Attrs().HardwareAddr
	eth := layers.Ethernet{
		SrcMAC:       hwAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(hwAddr),
		SourceProtAddress: []byte(dstAddr.To4()),
		DstHwAddress:      []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		DstProtAddress:    []byte(dstAddr.To4()),
		//DstProtAddress:    []byte(net.ParseIP("192.168.0.255").To4()),
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func getAddr(link netlink.Link, family int) (*netlink.Addr, error) {
	addrList, err := netlink.AddrList(link, family)
	if err != nil {
		return nil, err
	}
	return &addrList[0], nil
}

func showNeigh(link netlink.Link) {
	fmt.Printf("%s Neighbours:\n", link.Attrs().Name)
	neighList, err := netlink.NeighList(link.Attrs().Index, 0)
	if err != nil {
		panic(err)
	}
	for _, neigh := range neighList {
		fmt.Printf("  %v\n", &neigh)
	}
}

func showAddrs(link netlink.Link) {
	fmt.Printf("%s Addreses:\n", link.Attrs().Name)
	addrList, err := netlink.AddrList(link, 0)
	if err != nil {
		panic(err)
	}
	for _, addr := range addrList {
		fmt.Printf("  %v\n", &addr)
	}
}

func foo() {
	var wg sync.WaitGroup
	wg.Add(1)
	// Get local bridge
	brlocal, err := netlink.LinkByName(device)
	if err != nil {
		panic(err)
	}
	brlocalAddr, err := getAddr(brlocal, netlink.FAMILY_V4)
	if err != nil {
		panic(err)
	}
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	go func() {
		defer wg.Done()
		// Set filter
		//filter := fmt.Sprintf("host %s", dstAddr)
		filter := fmt.Sprintf("not port 1900 and not port 5353") // Ignore SSDP and MDNS traffic
		err = handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// Do something with a packet here.
			fmt.Printf("Received packet:\n%v", packet)
			//break
			// Show ARP table after ARP request
			showNeigh(brlocal)
		}
	}()

	// Show ARP table before ARP request
	showNeigh(brlocal)

	raw := unsolicitedArp(brlocal, brlocalAddr.IP, net.ParseIP(dstAddr))
	err = handle.WritePacketData(raw)
	if err != nil {
		panic(err)
	}

	// Show ARP table after ARP request
	showNeigh(brlocal)

	// XXX DO NOT EXIT - goroutine never exits
	wg.Wait()
}

func bar() {
	dockerNS, err := netns.GetFromDocker("cac25d2eca25")
	if err != nil {
		panic(err)
	}
	//netlink.executeInNetns(newNs, curNs netns.NsHandle) (func(), error) {
	dockerNL, err := netlink.NewHandleAt(dockerNS, 0)
	if err != nil {
		panic(err)
	}

	linkList, err := dockerNL.LinkList()
	if err != nil {
		panic(err)
	}
	for idx, l := range linkList {
		fmt.Printf("%d %v\n", idx, l.Attrs())
	}
}

func tun() {
	//tunLink, tunIO, err := ConnectTun("tunbraccept")
	tunLink, tunIO := ConnectTun("tunbraccept")
	defer func() {
		netlink.LinkDel(tunLink)
		tunIO.Close()
	}()

	showAddrs(tunLink)

	// Start scion_border container using docker-compose
	out, err := exec.Command(
		"docker-compose",
		"-f", "go/border/border-acceptance/docker-compose.yml",
		"up", "--detach",
		"dispatcher").CombinedOutput()
	//out, err := exec.Command("pwd").Output()
	fmt.Printf("%s\n", out)
	if err != nil {
		panic(err)
	}
	out, err = exec.Command(
		"docker-compose",
		"-f", "go/border/border-acceptance/docker-compose.yml",
		"up", "--detach").CombinedOutput()
	idRaw, err := exec.Command("docker", "ps", "-qf", "name=dispatcher").Output()
	id := strings.TrimSpace(string(idRaw))
	fmt.Printf("Container ID: %s\n", id)
	if err != nil {
		panic(err)
	}
	dockerNS, err := netns.GetFromDocker(id)
	if err != nil {
		panic(err)
	}
	//netlink.executeInNetns(newNs, curNs netns.NsHandle) (func(), error) {
	dockerNL, err := netlink.NewHandleAt(dockerNS, 0)
	if err != nil {
		panic(err)
	}

	linkList, err := dockerNL.LinkList()
	if err != nil {
		panic(err)
	}
	for idx, l := range linkList {
		fmt.Printf("%d %v\n", idx, l.Attrs())
	}

	if err := netlink.LinkSetNoMaster(tunLink); err != nil {
		panic(err)
	}
	if err := netlink.LinkSetNsFd(tunLink, int(dockerNS)); err != nil {
		panic(err)
	}
	// Start scion_border container using docker-compose
	out, err = exec.Command(
		"docker-compose",
		"-f", "go/border/border-acceptance/docker-compose.yml",
		"up", "--detach").CombinedOutput()
	//out, err := exec.Command("pwd").Output()
	fmt.Printf("%s\n", out)
	if err != nil {
		panic(err)
	}
	/*
		cli, err := client.NewClientWithOpts(client.WithVersion("3"))

		cli.ContainerCreate()
	*/
	linkList, err = dockerNL.LinkList()
	if err != nil {
		panic(err)
	}
	for idx, l := range linkList {
		fmt.Printf("%d %v\n", idx, l.Attrs())
	}
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func main() {
	tun()
	return

	bar()

	foo()

	// Get local bridge
	brlocal, err := netlink.LinkByName(device)
	if err != nil {
		panic(err)
	}

	/*
			tunLink, tunIO, err := ConnectTun("tunbraccept")
			if err != nil {
				panic(err)
			}
			defer func() {
				netlink.LinkDel(tunLink)
				tunIO.Close()
			}()

			showAddrs(tunLink)
					n, err := tunIO.Write(pkt)
					if err != nil {
						panic(err)
					}
				fmt.Printf("Written %d Bytes to tunIO\n", n)

		if err := netlink.LinkSetMaster(tunLink, brlocal.(*netlink.Bridge)); err != nil {
			panic(err)
		}

	*/
	// XXX DO NOT EXIT
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
	/*
		if err := netlink.BridgeSetMcastSnoop(brlocal, false); err != nil {
			panic(err)
		}
	*/
	var tt net.Interface
	tt = tt
	var temp netlink.Link
	temp = temp
	fmt.Printf("Link Attrs:\n%v\n", brlocal.Attrs())

	brlocalAddr, err := getAddr(brlocal, netlink.FAMILY_V4)
	if err != nil {
		panic(err)
	}
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	go func() {
		defer wg.Done()
		// Set filter
		//filter := fmt.Sprintf("host %s", dstAddr)
		filter := fmt.Sprintf("not port 1900 and not port 5353") // Ignore SSDP and MDNS traffic
		err = handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// Do something with a packet here.
			fmt.Printf("Received packet:\n%v", packet)
			//break
			// Show ARP table after ARP request
			showNeigh(brlocal)
		}
	}()

	// Show ARP table before ARP request
	showNeigh(brlocal)

	// Send ARP request for destination
	// The kernel/bridge ignores the reply. We could parse the reply and then add the entry.
	// Although we do not really need the entry given that we craft all packets.
	/*
		raw := arpReq(brlocal, brlocalAddr.IP, net.ParseIP(dstAddr))
		err = handle.WritePacketData(raw)
		if err != nil {
			panic(err)
		}
	*/
	// Try TCP connect to force ARP Request.
	// We rely on host iptables, NOT desirable.
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dstAddr, dstPort))
	if err == nil {
		conn.Close()
	}

	// XXX block forever because reader never exits
	wg.Wait()

	// Send packet
	rawBytes := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 1, 1, 1, 1}
	rawBytes = []byte{1, 2, 3, 4}

	// This time lets fill out some information
	ethernetLayer := &layers.Ethernet{
		DstMAC:       net.HardwareAddr{0x4a, 0x21, 0x51, 0x93, 0xde, 0xad},
		SrcMAC:       brlocal.Attrs().HardwareAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	fmt.Printf("ethernetLayer %v\n", ethernetLayer)
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		//Length:   uint16(20 + 8 + len(rawBytes)),
		SrcIP: brlocalAddr.IP,
		DstIP: net.ParseIP(dstAddr),
	}
	fmt.Printf("ipLayer %v\n", ipLayer)
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(40321),
		//DstPort: layers.UDPPort(30041),
		DstPort: layers.UDPPort(dstPort),
		//Length:   uint16(8 + len(rawBytes)),
		Checksum: 0,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	if err := buffer.Clear(); err != nil {
		panic(err)
	}
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		//&layers.Ethernet{},
		ipLayer,
		udpLayer,
		gopacket.Payload(rawBytes),
	); err != nil {
		panic(err)
	}
	pkt := buffer.Bytes()
	fmt.Printf("Packet hexdump len %d:\n%x\n", len(pkt), pkt)

	/*
		tunLink, tunIO, err := xnet.ConnectTun("tunbraccept")
		if err != nil {
			panic(err)
		}
		defer func() {
			netlink.LinkDel(tunLink)
			tunIO.Close()
		}()
			if err := netlink.LinkSetMaster(tunLink, brlocal.(*netlink.Bridge)); err != nil {
				panic(err)
			}

		n, err := tunIO.Write(pkt)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Written %d Bytes to tunIO\n", n)
	*/
	err = handle.WritePacketData(pkt)
	if err != nil {
		panic(err)
	}
	/*
		// FIXME use normal socket to send packets, we would need socket per interface
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
		if err != nil {
			fmt.Printf("%v", err)
		}

		f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
		n, err := f.Write(outgoingPacket)
		if err != nil {
			fmt.Printf("%v", err)
		}
		fmt.Printf("Wrote %d Bytes", n)

		addr := syscall.SockaddrInet4{
			Port: 40000,
			Addr: [4]byte{192, 168, 0, 2},
		}
		err = syscall.Sendto(fd, pkt, 0, &addr)
		if err != nil {
			fmt.Printf("Sendto: %v", err)
		}
	*/

	wg.Wait()
}

var Tests []BRTest = []BRTest{
	{
		BorderID: "CbrA", SrcIA: "1-ff00:0:2", DstIA: "1-ff00:0:5",
		In:   pktInfo{"br1201", overlayInfo{"192.168.12.2", 40000, "192.168.12.1", 50000}, 1, 2},
		Out:  []pktInfo{{"brlocal", overlayInfo{"192.168.0.11", 30087, "192.168.0.12", 30087}, 1, 2}},
		Segs: []segDef{{coreSeg, ifList{if_2A_1A}}, {downSeg, ifList{if_1B_5A}}},
	},
	{
		BorderID: "CbrA", SrcIA: "1-ff00:0:5", DstIA: "1-ff00:0:2",
		In:   pktInfo{"brlocal", overlayInfo{"192.168.0.12", 30087, "192.168.0.11", 30087}, 1, 2},
		Out:  []pktInfo{{"br1201", overlayInfo{"192.168.12.1", 50000, "192.168.12.2", 40000}, 2, 1}},
		Segs: []segDef{{upSeg, ifList{if_1B_5A}}, {coreSeg, ifList{if_2A_1A}}},
	},
	/*
		{
			BorderID: "CbrB", SrcIA: "1-ff00:0:2", DstIA: "1-ff00:0:5",
			In:   pktInfo{"brlocal", overlayInfo{"192.168.0.11", 30087, "192.168.0.12", 30087}, 1, 2},
			Out:  []pktInfo{{"br1501", overlayInfo{"192.168.15.1", 50000, "192.168.15.2", 40000}, 2, 1}},
			Segs: []segDef{{coreSeg, ifList{if_2A_1A}}, {downSeg, ifList{if_1B_5A}}},
		},
	*/
}

type segDef struct {
	segType segType
	segs    ifList
}

type ifList []common.IFIDType

type segType uint8

const (
	upSeg segType = iota + 1
	coreSeg
	downSeg
)

type overlayInfo struct {
	SrcAddr string
	SrcPort uint16
	DstAddr string
	DstPort uint16
}

type pktInfo struct {
	Bridge  string
	Overlay overlayInfo
	InfoF   int
	HopF    int
}

type BRTest struct {
	BorderID string
	SrcIA    string
	DstIA    string
	In       pktInfo
	Out      []pktInfo
	Segs     []segDef
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

var DefaultCoreGraphDescription = &graph.Description{
	Nodes: []string{
		"1-ff00:0:1",
		"1-ff00:0:2",
		"1-ff00:0:3",
		"1-ff00:0:4",
		"1-ff00:0:5",
	},
	// if_<src_16lsb_asid>_<dst_16lsb_asid>_<brnum>_<ifid>
	Edges: []graph.EdgeDesc{
		{"1-ff00:0:1", if_1A_2A, "1-ff00:0:2", if_2A_1A, false},
		{"1-ff00:0:1", if_1B_3A, "1-ff00:0:3", if_3A_1B, false},
		{"1-ff00:0:1", if_1B_4A, "1-ff00:0:4", if_4A_1B, false},
		{"1-ff00:0:1", if_1B_5A, "1-ff00:0:5", if_5A_1B, false},
		{"1-ff00:0:1", if_1C_4B, "1-ff00:0:4", if_4B_1C, false},
	},
}

/*
links:
  - {a: "1-ff00:0:1",   b: "1-ff00:0:2",   linkAtoB: CORE}
  - {a: "1-ff00:0:1-A", b: "2-ff00:0:3",   linkAtoB: CORE}
  - {a: "1-ff00:0:1-A", b: "1-ff00:0:4-A", linkAtoB: CORE}
  - {a: "1-ff00:0:1",   b: "1-ff00:0:4",   linkAtoB: CHILD}
  - {a: "1-ff00:0:3",   b: "1-ff00:0:4-A", linkAtoB: CHILD}
  - {a: "1-ff00:0:4-A", b: "1-ff00:0:5",   linkAtoB: PEER}
  - {a: "1-ff00:0:4",   b: "1-ff00:0:5",   linkAtoB: PEER}
  - {a: "1-ff00:0:4-A", b: "1-ff00:0:6",   linkAtoB: CHILD}
  - {a: "1-ff00:0:4",   b: "1-ff00:0:6",   linkAtoB: CHILD}
  - {a: "1-ff00:0:4-A", b: "1-ff00:0:7",   linkAtoB: CHILD}
  - {a: "1-ff00:0:4-A", b: "2-ff00:0:8",   linkAtoB: PEER}
*/
