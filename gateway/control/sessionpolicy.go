// Copyright 2020 Anapaya Systems
// Copyright 2026 SCION Association
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

package control

import (
	"context"
	"net"
	"os"

	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/path/pathpol"
)

// Default policies for session policies.
var (
	DefaultPathPolicy = &pathpol.Policy{
		ACL: &pathpol.ACL{
			Entries: []*pathpol.ACLEntry{{Action: pathpol.Allow}},
		},
	}
	DefaultPerfPolicy = fingerPrintOrder{}
	DefaultPathCount  = 1
)

// TrafficPolicyParser parses the traffic policy file into session policies. The file can use the
// legacy format or SessionPolicies.
type TrafficPolicyParser struct{}

// Parse parses the raw JSON into a SessionPolicies struct.
func (TrafficPolicyParser) Parse(ctx context.Context, raw []byte) (SessionPolicies, error) {
	sessionPolicies, warnings, err := parseTrafficPolicy(raw)
	logger := log.FromCtx(ctx)
	for _, w := range warnings {
		logWarning(logger, w)
	}
	if err != nil {
		return nil, err
	}
	return sessionPolicies, nil
}

func logWarning(logger log.Logger, w trafficPolicyWarning) {
	if w.IA != nil {
		logger = logger.New("isd_as", *w.IA)
	}
	if w.PolicyID != nil {
		logger = logger.New("session_policy_id", *w.PolicyID)
	}
	if w.PolicyName != "" {
		logger = logger.New("session_policy_name", w.PolicyName)
	}
	if w.Severe {
		logger.Error("Traffic policy file warning", "warning", w.Msg)
		return
	}
	logger.Info("Traffic policy file warning", "warning", w.Msg)
}

func parsePrefixes(rawNets []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(rawNets))
	for _, s := range rawNets {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, serrors.Wrap("parsing CIDR", err)
		}
		if !ip.Equal(ipnet.IP) {
			return nil, serrors.New("network must be canonical", "raw", s)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// SessionPolicyParser parses a raw session policy.
type SessionPolicyParser interface {
	Parse(context.Context, []byte) (SessionPolicies, error)
}

// SessionPolicies is a list of session policies.
type SessionPolicies []SessionPolicy

// LoadSessionPolicies loads the session policies from the given file, and
// parses it with the given parser.
func LoadSessionPolicies(ctx context.Context, file string,
	parser SessionPolicyParser) (SessionPolicies, error) {

	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, serrors.Wrap("reading file", err)
	}
	p, err := parser.Parse(ctx, raw)
	if err != nil {
		return nil, serrors.Wrap("parsing", err, "file", file)
	}
	return p, nil
}

// RemoteIAs returns all IAs that are in the session policies.
func (p SessionPolicies) RemoteIAs() []addr.IA {
	uniqueIAs := make(map[addr.IA]struct{}, len(p))
	for _, s := range p {
		uniqueIAs[s.IA] = struct{}{}
	}
	result := make([]addr.IA, 0, len(uniqueIAs))
	for ia := range uniqueIAs {
		result = append(result, ia)
	}
	return result
}

// Copy creates a deep copy of the session policies.
func (p SessionPolicies) Copy() SessionPolicies {
	copy := make(SessionPolicies, 0, len(p))
	for _, sp := range p {
		copy = append(copy, sp.Copy())
	}
	return copy
}

// SessionPolicy specifies the policy for a session towards a remote AS. The policy for a session
// consists of a
// - remote IA, identifying the remote this policy is for,
// - policy id, together with the remote IA uniquely identifying the policy,
// - an optional name,
// - traffic class, defined by a traffic matcher,
// - a path policy,
// - a performance policy,
// - a path count,
// - a remote IA,
// - a set of prefixes.
type SessionPolicy struct {
	// IA is the ISD-AS number of the remote AS.
	IA addr.IA
	// ID identifies a session policy to a remote AS, i.e., the tuple (IA, ID) is unique.
	ID int
	// Name is the optional name of the session policy.
	Name string
	// TrafficMatcher contains the conditions the IP traffic must satisfy to use
	// this session.
	TrafficMatcher pktcls.Cond
	// PerfPolicy specifies which paths should be preferred (e.g., the path with
	// the lowest latency). The path selector does not use it yet.
	PerfPolicy policies.PerfPolicy
	// PathPolicy specifies the path properties that paths used for this session
	// must satisfy.
	PathPolicy policies.PathPolicy
	// PathCount  defines the number of paths that can be simultaneously used
	// within a session.
	PathCount int
	// Prefixes contains the network prefixes that are reachable through this
	// session.
	Prefixes []*net.IPNet
}

// Copy returns a copy of the session policy. The copy shares PathPolicy and PerfPolicy,
// because no code changes them after the parser creates them.
func (sp SessionPolicy) Copy() SessionPolicy {
	return SessionPolicy{
		ID:             sp.ID,
		Name:           sp.Name,
		IA:             sp.IA,
		TrafficMatcher: copyTrafficMatcher(sp.TrafficMatcher),
		PerfPolicy:     sp.PerfPolicy,
		PathPolicy:     sp.PathPolicy,
		PathCount:      sp.PathCount,
		Prefixes:       copyPrefixes(sp.Prefixes),
	}
}

func copyTrafficMatcher(m pktcls.Cond) pktcls.Cond {
	copy, err := pktcls.BuildClassTree(m.String())
	if err != nil {
		panic(err)
	}
	return copy
}

func copyPrefixes(prefixes []*net.IPNet) []*net.IPNet {
	copy := make([]*net.IPNet, 0, len(prefixes))
	for _, p := range prefixes {
		copy = append(copy, &net.IPNet{
			IP:   append(p.IP[:0:0], p.IP...),
			Mask: append(p.Mask[:0:0], p.Mask...),
		})
	}
	return copy
}

type fingerPrintOrder struct{}

func (fingerPrintOrder) Better(x, y *policies.Stats) bool { return x.Fingerprint < y.Fingerprint }
