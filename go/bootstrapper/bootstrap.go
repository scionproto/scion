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
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"github.com/grandcat/zeroconf"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/miekg/dns"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"golang.org/x/net/context/ctxhttp"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"text/template"
	"time"
)

const (
	baseURL = "scion/discovery/v1"
	discoveryPort           uint16 = 8041
	discoveryServiceDNSName string = "_sciondiscovery._tcp"
	discoveryDDDSDNSName    string = "x-sciondiscovery:tcp"
	httpRequestTimeout			   = 2*time.Second

	sciondConfigTemplate string = `
[general]
    id = "sd{{ .IA.FileFmt false }}"
    config_dir = "{{ .ConfigDirectory }}"
[trust_db]
    connection = "gen-cache/sd{{ .IA.FileFmt false }}.trust.db"
[path_db]
    connection = "gen-cache/sd{{ .IA.FileFmt false }}.path.db"
`
)

var (
	channel           = make(chan string)
	dnsServersChannel = make(chan DNSInfo)
)

type templateContext struct {
	IA addr.IA
	IPAddress net.IP
	ConfigDirectory string
}

func tryBootstrapping() error {
	hintGenerators := []HintGenerator{
		&DHCPHintGenerator{},
		&DNSSDHintGenerator{},
		&MDNSSDHintGenerator{}}

	for i := 0; i < len(hintGenerators); i++ {
		generator := hintGenerators[i]
		go func() {
			defer log.HandlePanic()
			generator.Generate(channel)
		}()
	}

	for {
		log.Info("Bootstrapper is waiting for hints")
		address := <-channel
		topo, raw := fetchTopology(address)
		if topo == nil { continue }

		topologyPath := path.Join(cfg.SCIONFolder,"topology.json")
		err := ioutil.WriteFile(topologyPath, raw, 0644)
		if err != nil {
			log.Error("Bootstrapper could not store topology", "path", topologyPath, "err", err)
			return err
		}

		err = generateSciondConfig(topo)
		if err != nil {
			return err
		}

		err = pullTRCs(&net.TCPAddr{IP: net.ParseIP(address), Port: int(discoveryPort)})
		if err != nil { return err }
		break
	}
	return nil
}

func fetchTopology(address string) (topology.Topology, common.RawBytes) {
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	//params := discovery.FetchParams{Mode: discovery.Static, File: discovery.Endhost}

	ip := addr.HostFromIPStr(address).IP()

	if ip == nil {
		log.Info("Discovered invalid address", "address", address)
		return nil, nil
	}
	//discovery.FetchTopoRaw(ctx, params, &addr.AppAddr{L3: ip, L4: addr.NewL4TCPInfo(discoveryPort)}, nil)
	topo, raw, err := fetchTopoHttp(ctx, &net.TCPAddr{IP:ip, Port: int(discoveryPort)})
	if err != nil {
		log.Info("Error fetching topology", "err", err)
		return nil, nil
	}
	return topo, raw
}

func fetchTopoHttp(ctx context.Context, ds *net.TCPAddr) (topology.Topology, common.RawBytes, error) {
	url := fmt.Sprintf("%s://%s:%d/%s", "http", ds.IP, ds.Port, baseURL + "/topology.json")
	log.Info("Fetching topology from " + url)
	rep, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, nil, common.NewBasicError("HTTP request failed", err)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return nil, nil, common.NewBasicError("Status not OK", nil, "status", rep.Status)
	}
	raw, err := ioutil.ReadAll(rep.Body)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to read body", err)
	}
	rwTopo, err := topology.RWTopologyFromJSONBytes(raw)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to parse RWTopology from JSON bytes", err)
	}
	return topology.FromRWTopology(rwTopo), raw, nil
}

func pullTRCs(addr *net.TCPAddr) error {
	url := fmt.Sprintf("%s://%s:%d/%s", "http", addr.IP, addr.Port, baseURL + "/trcs.tar.gz")
	log.Info("Fetching TRCs", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	rep, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return common.NewBasicError("HTTP request failed", err)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return common.NewBasicError("Status not OK", nil, "status", rep.Status)
	}

	// Extract TRCs gzip tar archive
	zr, err := gzip.NewReader(rep.Body)
	if err != nil {
		return common.NewBasicError("Unable to read body as gzip", err)
	}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return common.NewBasicError("error reading tar archive", err)
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			log.Info("Extracting TRC", "name", hdr.Name)
			trcPath := path.Join(cfg.SCIONFolder, "certs", hdr.Name)
			f, err := os.OpenFile(trcPath, os.O_CREATE|os.O_RDWR, 0644)
			if err != nil {
				return common.NewBasicError("error creating file to store TRC", err)
			}
			_, err = io.Copy(f, tr)
			if err != nil {
				return common.NewBasicError("error writing TRC file", err)
			}
		case tar.TypeDir:
			return fmt.Errorf("TRCs archive must be composed of TRCs only, directory found")
		default:
			return fmt.Errorf("TRCs archive must be composed of TRCs only, unknown type found: %c", hdr.Typeflag)
		}
	}
	if err := zr.Close(); err != nil {
		return common.NewBasicError("error closing gunzip reader", err)
	}
	return nil
}

func generateSciondConfig(topo topology.Topology) error {
	t := template.Must(template.New("config").Parse(sciondConfigTemplate))
	sciondFile, err := os.OpenFile(cfg.SCIONFolder+ "/sd.toml", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Error("Could not open sciond config file", "err", err)
		return err
	}
	address := getIPAddress()
	if address == nil {
		return errors.New("")
	}
	ctx := templateContext{
		IA: topo.IA(),
		IPAddress: address,
		ConfigDirectory: cfg.SCIONFolder,
	}
	err = t.Execute(sciondFile, ctx)
	if err != nil {
		log.Error("Could not template sciond config file", "err", err)
		return err
	}
	return nil
}

type HintGenerator interface {
	Generate(resultChannel chan string)
}

var _ HintGenerator = (*DHCPHintGenerator)(nil)

type DHCPHintGenerator struct{}

func (g *DHCPHintGenerator) Generate(channel chan string) {
	if ! cfg.Mechanisms.DHCP {
		return
	}

	intf := getInterface()
	if intf == nil {
		return
	}
	probeInterface(intf, channel)
}

func probeInterface(currentInterface *net.Interface, channel chan string) {
	log.Info("DHCP Probing", "interface", currentInterface.Name)
	client := client4.NewClient()
	localIPs, err := dhcpv4.IPv4AddrsForInterface(currentInterface)
	if err != nil || len(localIPs) == 0 {
		log.Error("DHCP hinter could not get local IPs", "interface", currentInterface.Name, "err", err)
		return
	}
	p, err := dhcpv4.NewInform(currentInterface.HardwareAddr, localIPs[0], dhcpv4.WithRequestedOptions(
		dhcpv4.OptionDefaultWorldWideWebServer,
		dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDNSDomainSearchList))
	if err != nil {
		log.Error("DHCP hinter failed to build network packet", "interface", currentInterface.Name, "err", err)
		return
	}
	p.SetBroadcast()
	sender, err := client4.MakeBroadcastSocket(currentInterface.Name)
	if err != nil {
		log.Error("DHCP hinter failed to open broadcast sender socket", "interface", currentInterface.Name, "err", err)
		return
	}
	receiver, err := client4.MakeListeningSocket(currentInterface.Name)
	if err != nil {
		log.Error("DHCP hinter failed to open receiver socket", "interface", currentInterface.Name, "err", err)
		return
	}
	now := time.Now().UnixNano()
	ack, err := client.SendReceive(sender, receiver, p, dhcpv4.MessageTypeAck)
	then := time.Now().UnixNano()
	log.Debug("timing", "type", "dhcp", "value", (then - now))
	if err != nil {
		log.Error("DHCP hinter failed to send inform request", "interface", currentInterface.Name, "err", err)
		return
	}
	ips := dhcpv4.GetIPs(dhcpv4.OptionDefaultWorldWideWebServer, ack.Options)
	if ips != nil {
		for _, ip := range ips {
			log.Info("DHCP hint", "IP", ip)
			channel <- ip.String()
		}
	}

	resolvers := dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options)
	rawSearchDomains := ack.Options.Get(dhcpv4.OptionDNSDomainSearchList)
	searchDomains, err := rfc1035label.FromBytes(rawSearchDomains)

	if err != nil {
		log.Error("DHCP failed to to read search domains", "err", err)
		// don't return, proceed without search domains
	}

	dnsInfo := DNSInfo{}

	for _, item := range resolvers {
		dnsInfo.resolvers = append(dnsInfo.resolvers, item.String())
	}

	if searchDomains != nil {
		for _, item := range searchDomains.Labels {
			dnsInfo.searchDomains = append(dnsInfo.searchDomains, item)
		}
	} else {
		dnsInfo.searchDomains = []string{}
	}

	dnsServersChannel <- dnsInfo
}

var _ HintGenerator = (*DNSSDHintGenerator)(nil)

// Domain Name System Service Discovery
type DNSSDHintGenerator struct{}

func (g *DNSSDHintGenerator) Generate(channel chan string) {
	for {
		dnsServer := <-dnsServersChannel
		dnsServer.searchDomains = append(dnsServer.searchDomains, getDomainName())

		for _, resolver := range dnsServer.resolvers {
			for _, domain := range dnsServer.searchDomains {
				if cfg.Mechanisms.DNSSD {
					doServiceDiscovery(channel, resolver, domain)
				}
				if cfg.Mechanisms.DNSNAPTR {
					doSNAPTRDiscovery(channel, resolver, domain)
				}
			}
		}
	}
}

type DNSInfo struct {
	resolvers	 []string
	searchDomains []string
}

func doServiceDiscovery(channel chan string, resolver, domain string) {
	query := discoveryServiceDNSName + "." + domain + "."
	log.Info("DNS-SD", "query", query, "rr", dns.TypePTR, "resolver", resolver)
	now := time.Now().UnixNano()
	resolveDNS(resolver, query, dns.TypePTR, channel)
	then := time.Now().UnixNano()
	log.Debug("timing", "type", "dnssd", "value", (then - now))
}

// Straightforward Naming Authority Pointer
func doSNAPTRDiscovery(channel chan string, resolver, domain string) {
	query := domain + "."
	log.Info("DNS-S-NAPTR", "query", query, "rr", dns.TypeNAPTR, "resolver", resolver)
	now := time.Now().UnixNano()
	resolveDNS(resolver, query, dns.TypeNAPTR, channel)
	then := time.Now().UnixNano()
	log.Debug("timing", "type", "dnssnaptr", "value", (then - now))
}

func resolveDNS(resolver, query string, dnsRR uint16, channel chan string) {
	msg := new(dns.Msg)
	msg.SetQuestion(query, dnsRR)
	msg.RecursionDesired = true
	result, err := dns.Exchange(msg, resolver+":53")
	if err != nil {
		log.Error("DNS-SD failed", "err", err)
		return
	}

	var serviceRecords []dns.SRV
	var naptrRecords []dns.NAPTR
	for _, answer := range result.Answer {
		log.Info("DNS", "answer", answer)
		switch answer.(type) {
		case *dns.PTR:
			result := *(answer.(*dns.PTR))
			resolveDNS(resolver, result.Ptr, dns.TypeSRV, channel)
		case *dns.NAPTR:
			result := *(answer.(*dns.NAPTR))
			if result.Service == discoveryDDDSDNSName {
				naptrRecords = append(naptrRecords, result)
			}
		case *dns.SRV:
			result := *(answer.(*dns.SRV))
			if result.Port != discoveryPort {
				log.Error("DNS announced invalid discovery port", "expected", discoveryPort, "actual", result.Port)
			}
			serviceRecords = append(serviceRecords, result)
		case *dns.A:
			result := *(answer.(*dns.A))
			log.Info("DNS hint", "IP", result.A.String())
			channel <- result.A.String()
		case *dns.AAAA:
			result := *(answer.(*dns.AAAA))
			log.Info("DNS hint", "IP", result.AAAA.String())
			channel <- result.AAAA.String()
		}
	}

	if len(serviceRecords) > 0 {
		sort.Sort(byPriority(serviceRecords))

		for _, answer := range serviceRecords {
			resolveDNS(resolver, answer.Target, dns.TypeAAAA, channel)
			resolveDNS(resolver, answer.Target, dns.TypeA, channel)
		}
	}

	if len(naptrRecords) > 0 {
		sort.Sort(byOrder(naptrRecords))

		for _, answer := range naptrRecords {
			switch answer.Flags {
			case "":
				resolveDNS(resolver, answer.Replacement, dns.TypeNAPTR, channel)
			case "A":
				resolveDNS(resolver, answer.Replacement, dns.TypeAAAA, channel)
				resolveDNS(resolver, answer.Replacement, dns.TypeA, channel)
			case "S":
				resolveDNS(resolver, answer.Replacement, dns.TypeSRV, channel)
			}
		}
	}
}

var _ HintGenerator = (*MDNSSDHintGenerator)(nil)

// Multicast Domain Name System Service Discovery
type MDNSSDHintGenerator struct{}

func (g *MDNSSDHintGenerator) Generate(channel chan string) {
	if ! cfg.Mechanisms.MDNS {
		return
	}
	intf := getInterface()
	if intf == nil {
		return
	}

	resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{*intf}))
	if err != nil {
		log.Error("mDNS could not construct dns resolver", "err", err)
		return
	}

	var now int64
	entries := make(chan *zeroconf.ServiceEntry)
	go func(now *int64, results <-chan *zeroconf.ServiceEntry) {
		defer log.HandlePanic()
		then := time.Now().UnixNano()
		log.Debug("timing", "type", "mdns", "value", (then - *now))
		for entry := range results {
			for _, address := range entry.AddrIPv4 {
				log.Info("mDNS hint", "IP", address.String())
				channel <- address.String()
			}
			for _, address := range entry.AddrIPv6 {
				log.Info("mDNS hint", "IP", address.String())
				channel <- address.String()
			}
		}
		log.Info("mDNS has no more entries.")
	}(&now, entries)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	now = time.Now().UnixNano()
	err = resolver.Browse(ctx, "_sciondiscovery._tcp", "local.", entries)
	if err != nil {
		log.Error("mDNS could not lookup", "err", err)
		return
	}
	<-ctx.Done()
}

func getInterface() *net.Interface {
	intf, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		log.Error("Bootstrapper could not get interface", "err", err)
		return nil
	}
	return intf
}

func getIPAddress() net.IP {
	intf := getInterface()
	if intf == nil {
		return nil
	}
	addresses, err := intf.Addrs()
	if err != nil {
		log.Error("Bootstrapper could not get IP address", "err", err)
		return nil
	}
	var address net.IP
	found := false
	for _, a := range addresses {
		switch v := a.(type) {
		case *net.IPNet:
			address = v.IP
			found = true
		case *net.IPAddr:
			address = v.IP
			found = true
		}
		if found {
			break
		}
	}
	return address
}

func getDomainName() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Error("Bootstrapper could not get hostname", "err", err)
		return ""
	}
	split := strings.SplitAfterN(hostname, ".", 2)
	if len(split) < 2 {
		log.Debug("Bootstrapper could not get domain name", "hostname", hostname, "split", split)
		return ""
	} else {
		log.Info("Bootstrapper", "domain", split[1])
	}
	return split[1]
}

// Order as defined by DNS-SD RFC
type byPriority []dns.SRV

func (s byPriority) Len() int {
	return len(s)
}

func (s byPriority) Less(i, j int) bool {
	if s[i].Priority < s[j].Priority {
		return true
	} else if s[j].Priority < s[i].Priority {
		return false
	} else {
		if s[i].Weight == 0 && s[j].Weight == 0 {
			return rand.Intn(2) == 0
		}
		max := int(s[i].Weight) + int(s[j].Weight)
		return rand.Intn(max) < int(s[i].Weight)
	}
}

func (s byPriority) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Order as defined by RFC
type byOrder []dns.NAPTR

func (s byOrder) Len() int {
	return len(s)
}

func (s byOrder) Less(i, j int) bool {
	if s[i].Order < s[j].Order {
		return true
	} else if s[j].Order < s[i].Order {
		return false
	} else {
		return s[i].Preference < s[j].Preference
	}
}

func (s byOrder) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Glue to provide fetched topology
type providerFunc func() topology.Topology

func (f providerFunc) Get() topology.Topology {
	return f()
}
