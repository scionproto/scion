// Copyright 2021 Anapaya Systems
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

package fake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	fakedaemon "github.com/scionproto/scion/go/lib/daemon/fake"
	"github.com/scionproto/scion/go/lib/pktcls"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers/path"
	"github.com/scionproto/scion/go/lib/slayers/path/scion"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/pkg/gateway/control"
)

// Config is the fake gateway configuration.
type Config struct {
	LocalIA  addr.IA
	Chains   []*control.RoutingChain
	Sessions []*Session
}

// ParseConfig parse the fake gateway configuration from the given reader.
func ParseConfig(reader io.Reader, creationTime time.Time) (*Config, error) {
	var rawCfg rawConfig
	if err := json.NewDecoder(reader).Decode(&rawCfg); err != nil {
		return nil, serrors.WrapStr("decoding JSON", err)
	}
	cfg := &Config{
		LocalIA:  rawCfg.LocalIsdAs,
		Chains:   make([]*control.RoutingChain, 0, len(rawCfg.RoutingChains)),
		Sessions: make([]*Session, 0, len(rawCfg.Sessions)),
	}
	remotes := make(map[int]addr.IA)
	for _, rc := range rawCfg.RoutingChains {
		prefixes, err := parsePrefixes(rc.Prefixes)
		if err != nil {
			return nil, err
		}
		matchers, err := parseTrafficMatchers(rc.TrafficMatchers)
		if err != nil {
			return nil, err
		}
		for _, m := range matchers {
			remotes[m.ID] = rc.RemoteIsdAs
		}
		c := &control.RoutingChain{
			RemoteIA:        rc.RemoteIsdAs,
			Prefixes:        prefixes,
			TrafficMatchers: matchers,
		}
		cfg.Chains = append(cfg.Chains, c)
	}
	for _, rs := range rawCfg.Sessions {
		s, err := parseSession(rs, creationTime)
		if err != nil {
			return nil, err
		}
		var ok bool
		s.RemoteIA, ok = remotes[s.ID]
		if !ok {
			return nil, serrors.New("no traffic matcher for session", "id", s.ID)
		}
		cfg.Sessions = append(cfg.Sessions, s)
	}
	return cfg, nil
}

// ConfigHandler allows to publish new configurations.
type ConfigHandler struct {
	ConfigUpdates chan<- *Config
}

func (h ConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		c, err := ParseConfig(r.Body, time.Now())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse config: %v", err), http.StatusBadRequest)
			return
		}
		h.ConfigUpdates <- c
	default:
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
	}
}

// LocalIAExtractor extracts the local IA from the config updates. It extracts
// only once and writes it to the local IA channel. All configurations are
// forwared.
type LocalIAExtractor struct {
	ConfigUpdatesRead <-chan *Config
	ConfigUpdateWrite chan<- *Config
	LocalIA           chan<- addr.IA

	notified bool
}

// Run runs the forwarder.
func (e LocalIAExtractor) Run() {
	for c := range e.ConfigUpdatesRead {
		if !e.notified {
			e.LocalIA <- c.LocalIA
			e.notified = true
		}
		e.ConfigUpdateWrite <- c
	}
}

// Session is a fake session for the gateway.
type Session struct {
	ID         int
	PolicyID   int
	IsUp       bool
	RemoteAddr *net.UDPAddr
	RemoteIA   addr.IA
	Paths      []snet.Path
}

type rawConfig struct {
	LocalIsdAs    addr.IA           `json:"local_isd_as"`
	RoutingChains []rawRoutingChain `json:"routing_chains"`
	Sessions      []rawSession      `json:"sessions"`
}

type rawTrafficMatcher struct {
	ID      int    `json:"id"`
	Matcher string `json:"matcher"`
}

type rawRoutingChain struct {
	RemoteIsdAs     addr.IA             `json:"remote_isd_as"`
	Prefixes        []string            `json:"prefixes"`
	TrafficMatchers []rawTrafficMatcher `json:"traffic_matchers"`
}

type rawPathHopFields struct {
	IsdAs   addr.IA `json:"isd_as"`
	Ingress uint16  `json:"ingress"`
	Egress  uint16  `json:"egress"`
	ExpTime uint8   `json:"exp_time"`
	Key     []byte  `json:"key"`
}

type rawPath struct {
	HopFields      []rawPathHopFields  `json:"hop_fields"`
	NextHop        *fakedaemon.UDPAddr `json:"next_hop"`
	MTU            uint16              `json:"mtu"`
	ForwardingPath string              `json:"forwarding_path"`
}

type rawSession struct {
	ID       int                 `json:"id"`
	Status   string              `json:"status"`
	PolicyID *int                `json:"policy_id"`
	Remote   *fakedaemon.UDPAddr `json:"remote"`
	Paths    []rawPath           `json:"paths"`
}

func parseSession(rawSession rawSession, creationTime time.Time) (*Session, error) {
	paths, err := parsePaths(rawSession.Paths, creationTime)
	if err != nil {
		return nil, err
	}
	policyID := rawSession.ID
	if rawSession.PolicyID != nil {
		policyID = *rawSession.PolicyID
	}
	s := &Session{
		ID:         rawSession.ID,
		PolicyID:   policyID,
		IsUp:       rawSession.Status == "up",
		RemoteAddr: (*net.UDPAddr)(rawSession.Remote),
		Paths:      paths,
	}
	return s, nil
}

func parsePaths(rawPaths []rawPath, creationTime time.Time) ([]snet.Path, error) {
	paths := make([]snet.Path, 0, len(rawPaths))
	for i, rp := range rawPaths {
		p, err := parsePath(rp, creationTime)
		if err != nil {
			return nil, serrors.WrapStr("parsing path", err, "idx", i)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

func parsePath(rawPath rawPath, creationTime time.Time) (snet.Path, error) {
	numHops := len(rawPath.HopFields)

	if numHops == 0 {
		return nil, serrors.New("parsing path without hop fields")
	}

	initialSegID := uint16(0x111)
	sp := &scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				CurrHF: 0,
				SegLen: [3]uint8{uint8(numHops), 0, 0},
			},
			NumINF:  1,
			NumHops: numHops,
		},
		InfoFields: []*path.InfoField{
			{
				SegID:     initialSegID,
				ConsDir:   true,
				Timestamp: uint32(creationTime.Unix()),
			},
		},
	}
	ifaces := make([]snet.PathInterface, 0, numHops*2)
	for _, rawHF := range rawPath.HopFields {
		if rawHF.Ingress != 0 {
			ifaces = append(ifaces, snet.PathInterface{
				ID: common.IFIDType(rawHF.Ingress),
				IA: rawHF.IsdAs,
			})
		}
		if rawHF.Egress != 0 {
			ifaces = append(ifaces, snet.PathInterface{
				ID: common.IFIDType(rawHF.Egress),
				IA: rawHF.IsdAs,
			})
		}
		hf := &path.HopField{
			ConsIngress: rawHF.Ingress,
			ConsEgress:  rawHF.Egress,
			ExpTime:     rawHF.ExpTime,
		}
		sp.HopFields = append(sp.HopFields, hf)
		macGen, err := scrypto.HFMacFactory(rawHF.Key)
		if err != nil {
			return nil, err
		}
		hf.Mac = path.MAC(macGen(), sp.InfoFields[0], hf)
		sp.InfoFields[0].UpdateSegID(hf.Mac)
	}
	sp.InfoFields[0].SegID = initialSegID

	var fwPath []byte
	if rawPath.ForwardingPath == "" {
		// empty SCION path with correct length:
		fwPath = make([]byte, scion.MetaLen+path.InfoLen+path.HopLen*numHops)
		if err := sp.SerializeTo(fwPath); err != nil {
			return nil, serrors.WrapStr("serializing forwarding path", err)
		}
	} else {
		var err error
		fwPath, err = base64.StdEncoding.DecodeString(rawPath.ForwardingPath)
		if err != nil {
			return nil, serrors.WrapStr("decoding base64 of forwarding path", err)
		}
	}

	p := snetpath.Path{
		Dst: ifaces[len(ifaces)-1].IA,
		SPath: spath.Path{
			Raw:  fwPath,
			Type: scion.PathType,
		},
		NextHop: (*net.UDPAddr)(rawPath.NextHop),
		Meta: snet.PathMetadata{
			Interfaces: ifaces,
			MTU:        rawPath.MTU,
			Expiry:     creationTime.Add(24 * time.Hour),
		},
	}
	return p, nil
}

func parseTrafficMatchers(rawMatchers []rawTrafficMatcher) ([]control.TrafficMatcher, error) {
	matchers := make([]control.TrafficMatcher, 0, len(rawMatchers))
	for _, rm := range rawMatchers {
		c, err := pktcls.BuildClassTree(rm.Matcher)
		if err != nil {
			return nil, serrors.WrapStr("parsing traffic matcher", err)
		}
		m := control.TrafficMatcher{
			ID:      rm.ID,
			Matcher: c,
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

func parsePrefixes(rawPrefixes []string) ([]*net.IPNet, error) {
	prefixes := make([]*net.IPNet, 0, len(rawPrefixes))
	for _, rp := range rawPrefixes {
		_, p, err := net.ParseCIDR(rp)
		if err != nil {
			return nil, serrors.WrapStr("parsing CIDR", err, "cidr", rp)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}
