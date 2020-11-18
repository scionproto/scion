package hinting

import (
	"github.com/miekg/dns"
	"github.com/scionproto/scion/go/lib/log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
)

const (
	discoveryServiceDNSName string = "_sciondiscovery._tcp"
	discoveryDDDSDNSName    string = "x-sciondiscovery:tcp"
)

var (
	dnsServersChan = make(chan DNSInfo)
)

type DNSHintGeneratorConf struct {
	EnableSD    bool `toml:"enable_sd"`
	EnableNAPTR bool `toml:"enable_naptr"`
}

var _ HintGenerator = (*DNSSDHintGenerator)(nil)

// DNSSDHintGenerator implements the Domain Name System Service Discovery
type DNSSDHintGenerator struct {
	cfg *DNSHintGeneratorConf
}

func NewDNSSDHintGenerator(cfg *DNSHintGeneratorConf) *DNSSDHintGenerator {
	return &DNSSDHintGenerator{cfg}
}

func (g *DNSSDHintGenerator) Generate(ipHintsChan chan net.IP) {
	for dnsServer := range dnsServersChan {
		dnsServer.searchDomains = append(dnsServer.searchDomains, getDomainName())

		for _, resolver := range dnsServer.resolvers {
			for _, domain := range dnsServer.searchDomains {
				if g.cfg.EnableSD {
					query := getDNSSDQuery(resolver, domain)
					resolveDNS(resolver, query, dns.TypePTR, ipHintsChan)
				}
				if g.cfg.EnableNAPTR {
					query := getDNSNAPTRQuery(resolver, domain)
					resolveDNS(resolver, query, dns.TypeNAPTR, ipHintsChan)
				}
			}
		}
	}
	log.Info("DNS hinting done")
}

type DNSInfo struct {
	resolvers     []string
	searchDomains []string
}

func getDNSSDQuery(resolver, domain string) string {
	query := discoveryServiceDNSName + "." + domain + "."
	log.Info("DNS-SD", "query", query, "rr", dns.TypePTR, "resolver", resolver)
	return query
}

// Straightforward Naming Authority Pointer
func getDNSNAPTRQuery(resolver, domain string) string {
	query := domain + "."
	log.Info("DNS-S-NAPTR", "query", query, "rr", dns.TypeNAPTR, "resolver", resolver)
	return query
}

func resolveDNS(resolver, query string, dnsRR uint16, ipHintsChan chan net.IP) {
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
			resolveDNS(resolver, result.Ptr, dns.TypeSRV, ipHintsChan)
		case *dns.NAPTR:
			result := *(answer.(*dns.NAPTR))
			if result.Service == discoveryDDDSDNSName {
				naptrRecords = append(naptrRecords, result)
			}
		case *dns.SRV:
			result := *(answer.(*dns.SRV))
			// TODO: Should we really consider different ports an error?
			if result.Port != DiscoveryPort {
				log.Error("DNS announced invalid discovery port", "expected", DiscoveryPort, "actual", result.Port)
			}
			serviceRecords = append(serviceRecords, result)
		case *dns.A:
			result := *(answer.(*dns.A))
			log.Info("DNS hint", "IP", result.A.String())
			ipHintsChan <- result.A
		case *dns.AAAA:
			result := *(answer.(*dns.AAAA))
			log.Info("DNS hint", "IP", result.AAAA.String())
			ipHintsChan <- result.AAAA
		}
	}

	if len(serviceRecords) > 0 {
		sort.Sort(byPriority(serviceRecords))

		for _, answer := range serviceRecords {
			resolveDNS(resolver, answer.Target, dns.TypeAAAA, ipHintsChan)
			resolveDNS(resolver, answer.Target, dns.TypeA, ipHintsChan)
		}
	}

	if len(naptrRecords) > 0 {
		sort.Sort(byOrder(naptrRecords))

		for _, answer := range naptrRecords {
			switch answer.Flags {
			case "":
				resolveDNS(resolver, answer.Replacement, dns.TypeNAPTR, ipHintsChan)
			case "A":
				resolveDNS(resolver, answer.Replacement, dns.TypeAAAA, ipHintsChan)
				resolveDNS(resolver, answer.Replacement, dns.TypeA, ipHintsChan)
			case "S":
				resolveDNS(resolver, answer.Replacement, dns.TypeSRV, ipHintsChan)
			}
		}
	}
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
