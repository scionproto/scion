// Copyright 2020 Anapaya Systems
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

package hinting

import (
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/insomniacslk/dhcp/rfc1035label"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

type DHCPHintGeneratorConf struct {
	Enable bool `toml:"Enable"`
}

var _ HintGenerator = (*DHCPHintGenerator)(nil)

type DHCPHintGenerator struct {
	cfg   *DHCPHintGeneratorConf
	iface *net.Interface
}

func NewDHCPHintGenerator(cfg *DHCPHintGeneratorConf, iface *net.Interface) *DHCPHintGenerator {
	return &DHCPHintGenerator{cfg, iface}
}

func (g *DHCPHintGenerator) Generate(ipHintsChan chan<- net.IP) {
	log.Info("DHCP Probing", "interface", g.iface.Name)
	p, err := g.createDHCPRequest()
	if err != nil {
		log.Error("Error creating DHCP request", "err", err)
		return
	}
	ack, err := g.sendReceive(p)
	if err != nil {
		log.Error("Error creating sending/receiving DHCP request/response", "err", err)
		return
	}
	g.dispatchIPHints(ack, ipHintsChan)
	g.dispatchDNSInfo(ack, dnsServersChan)
	log.Info("DHCP hinting done")
}

func (g *DHCPHintGenerator) createDHCPRequest() (*dhcpv4.DHCPv4, error) {
	localIPs, err := dhcpv4.IPv4AddrsForInterface(g.iface)
	if err != nil || len(localIPs) == 0 {
		return nil, common.NewBasicError("DHCP hinter could not get local IPs", err)
	}
	p, err := dhcpv4.NewInform(g.iface.HardwareAddr, localIPs[0], dhcpv4.WithRequestedOptions(
		dhcpv4.OptionDefaultWorldWideWebServer,
		dhcpv4.OptionDomainNameServer,
		dhcpv4.OptionDNSDomainSearchList))
	if err != nil {
		return nil, common.NewBasicError("DHCP hinter failed to build network packet", err)
	}
	return p, nil
}

func (g *DHCPHintGenerator) sendReceive(p *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	p.SetBroadcast()
	client := client4.NewClient()
	sender, err := client4.MakeBroadcastSocket(g.iface.Name)
	if err != nil {
		return nil, common.NewBasicError("DHCP hinter failed to open broadcast sender socket", err)
	}
	receiver, err := client4.MakeListeningSocket(g.iface.Name)
	if err != nil {
		return nil, common.NewBasicError("DHCP hinter failed to open receiver socket", err)
	}
	ack, err := client.SendReceive(sender, receiver, p, dhcpv4.MessageTypeAck)
	if err != nil {
		return nil, common.NewBasicError("DHCP hinter failed to send inform request", err)
	}
	return ack, nil
}

func (g *DHCPHintGenerator) dispatchIPHints(ack *dhcpv4.DHCPv4, ipHintChan chan<- net.IP) {
	if !g.cfg.Enable {
		return
	}
	ips := dhcpv4.GetIPs(dhcpv4.OptionDefaultWorldWideWebServer, ack.Options)
	for _, ip := range ips {
		log.Info("DHCP hint", "IP", ip)
		ipHintChan <- ip
	}
}

func (g *DHCPHintGenerator) dispatchDNSInfo(ack *dhcpv4.DHCPv4, serversChan chan DNSInfo) {
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
	serversChan <- dnsInfo
}
