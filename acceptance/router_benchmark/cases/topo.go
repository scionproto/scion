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

package cases

import (
	"fmt"
	"hash"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/scrypto"
)

// Topology (see accept/router_benchmark/conf/topology.json)
//    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
//                 |
//    AS3 (br3) ---+
//
// We're only executing and monitoring br1a. All the others are a fiction (except for the knowledge
// about them configured in br1a) from which we construct packets that get injected at one of the
// br1a interfaces.
//
// To reduce maintainers headaches, the topology follows a convention to assign addresses, so that
// an address can be derived from a minimal information:
// * AS-1 is the hub of the test. Others are hereafter called children.
// * All IPs are V4.
// * Interface numbers are equal to the index of AS to which they connect.
// * ISD/AS: <1 or 2>-ff00:0:<AS index>
// * subnets are 10.123.<child AS number> except internal subnets that are 10.123.10*<AS>.<rtr>
// * hosts are 10.123.s.<interface number>
// * Mac addressed (when we can choose) derive from the IP
// * Ports are always 50000 for external interfaces and 30042 for internal interfaces.
//
// Example:
// * AS2 has only interface number 1 with IP 10.123.2.2 and mac address f0:0d:cafe:02:02 that
//   connects to AS 1 interface number 2.
// * AS1's interface number 2 has IP 10.123.2.1 and mac address f0:0d:cafe:02:01.
// * AS1's 1st router interface 0 has IP 10.123.10.1 and mac address f0:0d:cafe:10:01.
//
// Functions are provided to generate all addresses following that scheme.

// intfDesc describes an interface requirement.
// The "exclusive" attribute is a directive to the test harness. It means that this connection must
// have an exclusive pair of physical interfaces. The test harness may assign multiple non-exclusive
// address pairs to the same pair of physical interfaces.
// Purpose: Each test case uses only one of the external interface so they can all share the same
// physical link, which simplifies the physical infrastructure of real devices tests.
type intfDesc struct {
	ip        netip.Addr
	peerIP    netip.Addr
	exclusive bool
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS (that is, the AS that this interface connects to).
// Per our scheme, the subnet number is the largest of the two AS numbers and the host is always
// the local AS. This works if there are no cycles. Else there could be subnet number collisions.
func PublicIP(localAS byte, remoteAS byte) netip.Addr {
	if addrOverride, found := pubIPoverrides[int(localAS)][int(remoteAS)]; found {
		return addrOverride
	}
	subnetNr := max(remoteAS, localAS)
	return netip.AddrFrom4([4]byte{10, 123, subnetNr, localAS})
}

// publicIP returns the IP address that is assigned to external interface designated by the given
// AS index and the peer AS, plus the port to go with.
func PublicIPPort(localAS byte, remoteAS byte) (netip.Addr, layers.UDPPort) {
	return PublicIP(localAS, remoteAS), layers.UDPPort(50000)
}

// internalIP returns the IP address that is assigned to the internal interface of the given
// router in the AS of the given index.
func InternalIP(AS byte, routerIndex byte) netip.Addr {
	if addrOverride, found := intIPoverrides[int(AS)][int(routerIndex)]; found {
		return addrOverride
	}
	return netip.AddrFrom4([4]byte{10, 123, AS * 10, routerIndex})
}

// internalIPPort returns internalIP and the UDPPort to go with.
func InternalIPPort(AS byte, routerIndex byte) (netip.Addr, layers.UDPPort) {
	return InternalIP(AS, routerIndex), layers.UDPPort(30042)
}

// PublicIP6 returns an IPv6 address for the external interface.
// Scheme: fd00:10:123:SS::LL where SS=subnet(max(local,remote)), LL=localAS.
func PublicIP6(localAS byte, remoteAS byte) netip.Addr {
	if addrOverride, found := pubIPoverrides[int(localAS)][int(remoteAS)]; found {
		return addrOverride
	}
	subnetNr := max(remoteAS, localAS)
	return netip.AddrFrom16([16]byte{
		0xfd, 0x00, 0x00, 0x10, 0x01, 0x23, 0x00, subnetNr,
		0, 0, 0, 0, 0, 0, 0, localAS,
	})
}

func PublicIP6Port(localAS byte, remoteAS byte) (netip.Addr, layers.UDPPort) {
	return PublicIP6(localAS, remoteAS), layers.UDPPort(50000)
}

// InternalIP6 returns an IPv6 address for the internal interface.
// Scheme: fd00:10:123:A0::RR where A0=AS*10, RR=routerIndex.
func InternalIP6(AS byte, routerIndex byte) netip.Addr {
	if addrOverride, found := intIPoverrides[int(AS)][int(routerIndex)]; found {
		return addrOverride
	}
	return netip.AddrFrom16([16]byte{
		0xfd, 0x00, 0x00, 0x10, 0x01, 0x23, 0x00, AS * 10,
		0, 0, 0, 0, 0, 0, 0, routerIndex,
	})
}

func InternalIP6Port(AS byte, routerIndex byte) (netip.Addr, layers.UDPPort) {
	return InternalIP6(AS, routerIndex), layers.UDPPort(30042)
}

// isdAS returns a complete string form ISD/AS number for the given AS index.
// All are in ISD-1, except AS 4.
func ISDAS(AS byte) addr.IA {
	if AS == 4 {
		return addr.MustParseIA(fmt.Sprintf("2-ff00:0:%d", AS))
	}
	return addr.MustParseIA(fmt.Sprintf("1-ff00:0:%d", AS))
}

func FakeMAC(AS byte) hash.Hash {
	macGen, err := scrypto.HFMacFactory([]byte{AS})
	if err != nil {
		panic(err)
	}
	return macGen()
}

func Underlay(
	srcIP netip.Addr,
	srcPort layers.UDPPort,
	dstIP netip.Addr,
	dstPort layers.UDPPort) (*layers.Ethernet, *layers.IPv4, *layers.UDP) {

	// Point-to-point.
	ethernet := &layers.Ethernet{
		SrcMAC:       MACAddr(srcIP),
		DstMAC:       MACAddr(dstIP),
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Point-to-point. This is the real IP: the underlay network.
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    srcIP.AsSlice(),
		DstIP:    dstIP.AsSlice(),
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	return ethernet, ip, udp
}

// Underlay6 constructs an IPv6 underlay (Ethernet + IPv6 + UDP) for benchmark packets.
func Underlay6(
	srcIP netip.Addr,
	srcPort layers.UDPPort,
	dstIP netip.Addr,
	dstPort layers.UDPPort) (*layers.Ethernet, *layers.IPv6, *layers.UDP) {

	ethernet := &layers.Ethernet{
		SrcMAC:       MACAddr(srcIP),
		DstMAC:       MACAddr(dstIP),
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      dstIP.AsSlice(),
		NextHeader: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	return ethernet, ip, udp
}

// interfaceLabel returns a string label for the given AS and interface indices.
// Such names are those used when responding to the show-interfaces command and when translating
// the --interface option.
func interfaceLabel(AS int, intf int) string {
	return fmt.Sprintf("%d_%d", AS, intf)
}

var (
	// intfMap lists the required interfaces. That's what we use to respond to showInterfaces
	intfMap map[string]intfDesc = map[string]intfDesc{}

	// deviceNames holds the real (os-given) names of our required network interfaces. It is
	// created and populated from the values of the --interface options by InitInterfaces.
	deviceNames map[string]string

	// macAddresses keeps the mac addresses associated with each IP. It is created and populated
	// from the values of the --interface options by InitInterfaces. There can be two items for each
	// interface since we record the neighbor's addresses too. Additional IPs not from intfMap have
	// no known mac addresses; we are free to make them up to make credible packets.
	macAddrs map[netip.Addr]net.HardwareAddr

	// override map for public ip addresses. Use those, rather than the autogenerated ones, if
	// instructed.  (Note, that it means that the topology file and router config have been changed
	// too).  Used as ipAddrs[localAS][remoteAS] == ip_addr_at_localAS
	pubIPoverrides map[int]map[int]netip.Addr

	// override map for internal ip addresses. Use those, rather than the autogenerated ones, if
	// instructed.  (Note, that it means that the topology file and router config have been changed
	// too).  Used as ipAddrs[AS][routerNb] == internal_ip_addr_at_router
	intIPoverrides map[int]map[int]netip.Addr
)

// InitPubIPoverrides takes an array of strings and generates a map.
// the format of each string is "localAS_remoteAS=IP". Where AS is an AS number.
func InitPubIPoverrides(pairs []string) {
	pubIPoverrides = make(map[int]map[int]netip.Addr)
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		ASes := strings.Split(p[0], "_")
		IP, err := netip.ParseAddr(p[1])
		if err != nil {
			panic(err)
		}
		localAS, err := strconv.Atoi(ASes[0])
		if err != nil {
			panic(err)
		}
		remoteAS, err := strconv.Atoi(ASes[1])
		if err != nil {
			panic(err)
		}
		if pubIPoverrides[localAS] == nil {
			pubIPoverrides[localAS] = make(map[int]netip.Addr)
		}
		pubIPoverrides[localAS][remoteAS] = IP
		fmt.Printf("pubIpOverride: localAS %d remoteAS %d IP %s\n",
			localAS, remoteAS, IP.String())
	}
}

// InitIntIPoverrides takes an array of strings and generates a map.
// the format of each string is "AS_router=IP". Where AS is an AS number and router is
// the index of one router.
func InitIntIPoverrides(pairs []string) {
	intIPoverrides = make(map[int]map[int]netip.Addr)
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		ASrouter := strings.Split(p[0], "_")
		IP, err := netip.ParseAddr(p[1])
		if err != nil {
			panic(err)
		}
		AS, err := strconv.Atoi(ASrouter[0])
		if err != nil {
			panic(err)
		}
		routerNb, err := strconv.Atoi(ASrouter[1])
		if err != nil {
			panic(err)
		}
		if intIPoverrides[AS] == nil {
			intIPoverrides[AS] = make(map[int]netip.Addr)
		}
		fmt.Printf("intIpOverride: AS %d router %d IP %s\n", AS, routerNb, IP.String())
		intIPoverrides[AS][routerNb] = IP
	}
}

func InitIntfMap() {
	intfMap = map[string]intfDesc{
		interfaceLabel(1, 0): {InternalIP(1, 1), InternalIP(1, 2), true},
		interfaceLabel(1, 2): {PublicIP(1, 2), PublicIP(2, 1), false},
		interfaceLabel(1, 3): {PublicIP(1, 3), PublicIP(3, 1), false},
	}
}

func InitIntfMap6() {
	intfMap = map[string]intfDesc{
		interfaceLabel(1, 0): {InternalIP6(1, 1), InternalIP6(1, 2), true},
		interfaceLabel(1, 2): {PublicIP6(1, 2), PublicIP6(2, 1), false},
		interfaceLabel(1, 3): {PublicIP6(1, 3), PublicIP6(3, 1), false},
	}
}

// InitInterfaces collects the names (OS device name) and mac addresses for the interfaces setup by
// the invoker according to instructions given via listInterfaces().
// This information is indexed by our own interface labels.
//
// Returns a list of unique device names that any label maps to. (i.e. devices that at least one
// test will need to open.
func InitInterfaces(pairs []string) []string {
	asSet := make(map[string]struct{}, len(pairs))
	deviceNames = make(map[string]string, len(pairs))
	macAddrs = make(map[netip.Addr]net.HardwareAddr, len(pairs)*2)
	for _, pair := range pairs {
		p := strings.Split(pair, "=")
		label := p[0]
		info := strings.Split(p[1], ",")
		name := info[0]
		deviceNames[label] = name // host-side name (brload's side)
		asSet[name] = struct{}{}
		subjectIP := intfMap[label].ip
		peerIP := intfMap[label].peerIP

		// Now find the MAC addresses, so we don't have to be told.
		device, err := net.InterfaceByName(name)
		if err != nil {
			panic(err)
		}

		// PeerMac (our side): By default we use the real one, but we can be told to use another.
		// (If the link is virtual ethernet, using the real mac address causes serious performance
		// issues: the kernel will waste time trying to process incoming packets and sending icmp
		// errors back).
		peerMAC := device.HardwareAddr
		if len(info) > 1 {
			peerMAC, err = net.ParseMAC(info[1])
			if err != nil {
				panic(err)
			}
		}

		if subjectIP.Is4() {
			// IPv4: use ARP to resolve the subject's MAC.
			subjectMAC := resolveARP(device, subjectIP, peerIP, peerMAC)
			macAddrs[subjectIP] = subjectMAC
			macAddrs[peerIP] = peerMAC
		} else {
			// IPv6: use NDP (via kernel) to resolve the subject's MAC.
			subjectMAC := resolveNDP(name, subjectIP, peerIP, peerMAC)
			macAddrs[subjectIP] = subjectMAC
			macAddrs[peerIP] = peerMAC
		}
	}
	deduped := make([]string, 0, len(asSet))
	for n := range asSet {
		deduped = append(deduped, n)
	}
	return deduped
}

// resolveARP resolves the subject's MAC via ARP and starts a background goroutine
// that responds to ARP requests from the subject.
func resolveARP(
	device *net.Interface,
	subjectIP netip.Addr,
	peerIP netip.Addr,
	peerMAC net.HardwareAddr,
) net.HardwareAddr {
	arpClient, err := arp.Dial(device)
	if err != nil {
		panic(err)
	}
	err = arpClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		panic(err)
	}
	subjectMAC, err := arpClient.Resolve(subjectIP)
	if err != nil {
		panic(fmt.Sprintf("read packet %s: %v", peerMAC, err))
	}

	// Respond to ARP requests so there's no need to add a static arp entry on the router side.
	err = arpClient.SetReadDeadline(time.Time{})
	if err != nil {
		panic(err)
	}
	go func() {
		defer log.HandlePanic()
		reply := arp.Packet{
			HardwareType:       1,
			ProtocolType:       uint16(ethernet.EtherTypeIPv4),
			HardwareAddrLength: 6,
			IPLength:           4,
			Operation:          arp.OperationReply,
			SenderHardwareAddr: peerMAC,
			SenderIP:           peerIP,
			TargetHardwareAddr: subjectMAC,
			TargetIP:           subjectIP,
		}
		for {
			p, _, err := arpClient.Read()
			if err == nil && p.SenderIP == subjectIP {
				_ = arpClient.WriteTo(&reply, subjectMAC)
			}
		}
	}()
	return subjectMAC
}

// resolveNDP resolves the subject's MAC via NDP (kernel-assisted).
// It assigns the peer IPv6 address to the interface, pings the subject to trigger NDP,
// reads the neighbor table, then removes the address. A static neighbor entry is added
// for the peer so the router can reach us without kernel-assigned addresses.
func resolveNDP(
	name string,
	subjectIP netip.Addr,
	peerIP netip.Addr,
	peerMAC net.HardwareAddr,
) net.HardwareAddr {
	// Assign the peer IP so the kernel can do NDP.
	cidr := fmt.Sprintf("%s/64", peerIP.String())
	_ = exec.Command("ip", "addr", "add", cidr, "dev", name).Run()

	// Flush any FAILED entries for this subject so NDP can retry.
	_ = exec.Command("ip", "-6", "neigh", "del", subjectIP.String(), "dev", name).Run()

	// Ping the subject to trigger NDP neighbor solicitation.
	_ = exec.Command("ping", "-6", "-c", "3", "-W", "2",
		"-I", name, subjectIP.String()).Run()

	// Read the neighbor table to get the resolved MAC.
	out, err := exec.Command("ip", "neigh", "show", subjectIP.String(),
		"dev", name).CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("ip neigh show %s dev %s: %s %v", subjectIP, name, out, err))
	}

	// Parse: "fd00:10:123:3::1 dev center_1 lladdr 58:a2:e1:04:a9:9a REACHABLE"
	fields := strings.Fields(strings.TrimSpace(string(out)))
	macIdx := -1
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) {
			macIdx = i + 1
			break
		}
	}
	if macIdx < 0 {
		panic(fmt.Sprintf("NDP resolution failed for %s on %s: %s", subjectIP, name, out))
	}
	subjectMAC, err := net.ParseMAC(fields[macIdx])
	if err != nil {
		panic(fmt.Sprintf("parsing MAC %q: %v", fields[macIdx], err))
	}

	// Add a static neighbor entry for the peer (us) so the router can reach brload.
	_ = exec.Command("ip", "neigh", "replace", peerIP.String(),
		"lladdr", peerMAC.String(), "dev", name, "nud", "permanent").Run()

	return subjectMAC
}

// interfaceName returns the name of the host interface that this test must use in order to exchange
// traffic with the interface designated by the given AS and interface indices.
func DeviceName(AS int, intf int) string {
	return deviceNames[interfaceLabel(AS, intf)]
}

// macAddr returns the mac address assigned to the interface that has the given IP address.
// if that address is imposed by our environment it is listed in the macAddrs map and that is what
// this function returns. Else, the address is made-up according to our scheme.
func MACAddr(ip netip.Addr) net.HardwareAddr {
	// Look it up or make it up.
	mac, ok := macAddrs[ip]
	if ok {
		return mac
	}

	// This component makes no assumption regarding how the topology is used. We have to support all
	// hosts that the topology describes, even fictional ones, should a test case refer to it.
	if ip.Is4() {
		as4 := ip.As4()
		return net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, as4[2], as4[3]}
	}
	// IPv6: use the last two bytes of the address.
	as16 := ip.As16()
	return net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, as16[14], as16[15]}
}

// hostAddr returns a the SCION Hosts addresse that corresponds to the given underlay address.
// Except for SVC addresses (which we do not support here), this is a restating of the underlay
// address.
func HostAddr(ip netip.Addr) addr.Host {
	return addr.HostIP(ip)
}

// ListInterfaces outputs a string describing the interfaces of the router under test.
// The invoker of this test gets this when using the show-interfaces command and is expected
// to set up the network accordingly before executing the test without that option.
// We do not choose interface names or mac addresses those will be provided by the invoker
// via the --interfaces options.
func ListInterfaces() string {
	var sb strings.Builder
	for l, i := range intfMap {
		prefixLen := "24"
		if i.ip.Is6() {
			prefixLen = "64"
		}
		sb.WriteString(l)
		sb.WriteString(",")
		sb.WriteString(prefixLen)
		sb.WriteString(",")
		sb.WriteString(i.ip.String())
		sb.WriteString(",")
		sb.WriteString(i.peerIP.String())
		sb.WriteString(",")
		sb.WriteString(strconv.FormatBool(i.exclusive))
		sb.WriteString("\n")
	}
	// "our_label,24,<ip on router side>,<ip on far side>\n"

	return sb.String()
}
