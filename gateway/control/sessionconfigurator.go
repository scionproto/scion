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

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/scionproto/scion/gateway/pathhealth/policies"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/path/pathpol"
	"github.com/scionproto/scion/private/worker"
)

// SessionConfig contains the data that describes a control-plane session.
type SessionConfig struct {
	// ID is the 1-byte session identifier that will be used to identify packets
	// on the wire.
	ID uint8
	// PolicyID is the ID of the SessionPolicy that lead to the creation of the SessionConfig.
	PolicyID int
	// IA is the ISD-AS number of the remote AS.
	IA addr.IA
	// TrafficMatcher contains the conditions the IP traffic must satisfy to use
	// this session.
	TrafficMatcher pktcls.Cond
	// PerfPolicy specifies which paths should be preferred (e.g., the path with
	// the lowest latency). If unset, paths with the lowest latency are
	// preferred.
	PerfPolicy policies.PerfPolicy
	// PathPolicy specifies the path properties that paths used for this session
	// must satisfy.
	PathPolicy policies.PathPolicy
	// PathCount is the max number of paths to use.
	PathCount int
	// Gateway describes a discovered remote gateway instance.
	Gateway Gateway
	// Prefixes contains the network prefixes that are reachable through this
	// session.
	Prefixes []*net.IPNet
}

// SessionConfigurator builds session configurations from the static traffic
// policy and the dynamic information from the discovery service.
type SessionConfigurator struct {
	// SessionPolicies is the channel from which traffic policy updates are read.
	SessionPolicies <-chan SessionPolicies
	// RoutingUpdates is the channel from which routing update information is
	// read.
	RoutingUpdates <-chan RemoteGateways
	// SessionConfigurations is the channel where new configurations are
	// published.
	SessionConfigurations chan<- []*SessionConfig

	stateMtx               sync.RWMutex
	currentSessionPolicies SessionPolicies
	currentRemotes         RemoteGateways
	configs                []*SessionConfig

	workerBase worker.Base
}

// Run informs the session configurator to start reading from its input channels
// and push updates on the configuration channel. It returns when the
// configurator terminates.
func (sc *SessionConfigurator) Run(ctx context.Context) error {
	return sc.workerBase.RunWrapper(ctx, sc.validate, sc.run)
}

// Close stops the session configurator.
func (sc *SessionConfigurator) Close(ctx context.Context) error {
	return sc.workerBase.CloseWrapper(ctx, nil)
}

// DiagnosticsWrite writes diagnostics to the writer.
func (sc *SessionConfigurator) DiagnosticsWrite(w io.Writer) {
	type sessionConfigDiagnostics struct {
		SessionPolicies SessionPolicies
		RemoteGateways  RemoteGateways
		SessionConfigs  []*SessionConfig
	}
	sc.stateMtx.RLock()
	defer sc.stateMtx.RUnlock()
	d := sessionConfigDiagnostics{
		SessionPolicies: sc.currentSessionPolicies,
		RemoteGateways:  sc.currentRemotes,
		SessionConfigs:  sc.configs,
	}
	raw, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		fmt.Fprintf(w, "Error writing SessionConfigurator diagnostics: %v", err)
		return
	}
	_, _ = w.Write(raw)
	fmt.Fprint(w, "\n")
}

func (sc *SessionConfigurator) run(ctx context.Context) error {
	logger := log.FromCtx(ctx)
	doLocked := func(l sync.Locker, f func()) {
		l.Lock()
		defer l.Unlock()
		f()
	}
	for {
		diff := false
		select {
		case currentSessionPolicies := <-sc.SessionPolicies:
			doLocked(&sc.stateMtx, func() {
				diff = diffSessionPolicies(sc.currentSessionPolicies, currentSessionPolicies)
				sc.currentSessionPolicies = currentSessionPolicies
			})
		case currentRemotes := <-sc.RoutingUpdates:
			doLocked(&sc.stateMtx, func() {
				diff = diffRoutingUpdates(sc.currentRemotes, currentRemotes)
				sc.currentRemotes = currentRemotes
			})
		case <-sc.workerBase.GetDoneChan():
			return nil
		}
		// if nothing changed we don't have to do anything.
		if !diff {
			continue
		}
		var configs []*SessionConfig
		var err error
		doLocked(&sc.stateMtx, func() {
			configs, err = buildSessionConfigs(sc.currentSessionPolicies, sc.currentRemotes)
			if err == nil {
				sc.configs = configs
			}
		})
		if err != nil {
			logger.Error("Failed to merge static and dynamic configs", "err", err)
			continue
		}
		logger.Debug("Sending configs through the channel", "configs", configs)
		sc.SessionConfigurations <- configs
		logger.Debug("Configs sent")
	}
}

func (sc *SessionConfigurator) validate(ctx context.Context) error {
	if sc.SessionPolicies == nil {
		return serrors.New("static updates channel must not be nil")
	}
	if sc.RoutingUpdates == nil {
		return serrors.New("dynamic updates channel must not be nil")
	}
	if sc.SessionConfigurations == nil {
		return serrors.New("configurations channel must not be nil")
	}
	return nil
}

// diffSessionPolicies tries to determine whether the 2 session policies lists
// differ. It ignores the ordering of the list and ignores duplicates
// (uniqueness on <IA, ID> pair). It returns true on differences and if it can't
// be clearly determined whether they differ.
func diffSessionPolicies(a, b SessionPolicies) bool {
	makeKey := func(sessPol SessionPolicy) string {
		return fmt.Sprintf("%s.%d", sessPol.IA, sessPol.ID)
	}
	mapA := make(map[string]SessionPolicy, len(a))
	mapB := make(map[string]SessionPolicy, len(b))
	fillMap := func(m map[string]SessionPolicy, policies SessionPolicies) {
		for _, sp := range policies {
			m[makeKey(sp)] = sp
		}
	}
	fillMap(mapA, a)
	fillMap(mapB, b)
	if len(mapA) != len(mapB) {
		return true
	}
	for key, entryA := range mapA {
		entryB, ok := mapB[key]
		if !ok {
			return true
		}
		if diffSessionPolicy(entryA, entryB) {
			return true
		}
	}
	return false
}

// diffSessionPolicy attempts to determine whether the 2 session policies
// differ. It returns true if they differ or if it can't be clearly determined
// if they differ.
func diffSessionPolicy(a, b SessionPolicy) bool {
	if a.TrafficMatcher.String() != b.TrafficMatcher.String() ||
		a.PathCount != b.PathCount ||
		// no better way than comparing pointers here:
		a.PerfPolicy != b.PerfPolicy ||
		prefixesKey(a.Prefixes) != prefixesKey(b.Prefixes) {
		return true
	}
	if a.PathPolicy == b.PathPolicy {
		return false
	}
	rawA, aErr := json.Marshal(a.PathPolicy)
	rawB, bErr := json.Marshal(b.PathPolicy)
	// in case of a marshalling error we can't decide further on equality so we
	// pessimistically assume a change.
	if aErr != nil || bErr != nil {
		return true
	}
	return !bytes.Equal(rawA, rawB)
}

// diffRoutingUpdates returns true if the 2 remote gateways information differ.
func diffRoutingUpdates(a, b RemoteGateways) bool {
	if len(a.Gateways) != len(b.Gateways) {
		return true
	}
	for ia, entryA := range a.Gateways {
		entryB, ok := b.Gateways[ia]
		if !ok {
			return true
		}
		if diffRemoteGateways(entryA, entryB) {
			return true
		}
	}
	return false
}

func diffRemoteGateways(a, b []RemoteGateway) bool {
	if len(a) != len(b) {
		return true
	}
	mapA := make(map[string]RemoteGateway, len(a))
	mapB := make(map[string]RemoteGateway, len(b))
	fillMap := func(m map[string]RemoteGateway, gateways []RemoteGateway) {
		for _, g := range gateways {
			m[g.Gateway.Control.String()] = g
		}
	}
	fillMap(mapA, a)
	fillMap(mapB, b)
	for key, entryA := range mapA {
		entryB, ok := mapB[key]
		if !ok {
			return true
		}
		if diffRemoteGateway(entryA, entryB) {
			return true
		}
	}
	return false
}

func diffRemoteGateway(a, b RemoteGateway) bool {
	return !a.Gateway.Equal(b.Gateway) ||
		prefixesKey(a.Prefixes) != prefixesKey(b.Prefixes)
}

// buildSessionConfigs builds the session configurations from the static
// configuration and the dynamic routing update. Only entries that are in the
// static configuration are considered. That means if the dynamic update
// contains an IA that is not statically configured it's ignored (might happen
// on removal of an IA). If the static configuration is nil an empty list is
// returned.
func buildSessionConfigs(sessionPolicies SessionPolicies,
	remoteGateways RemoteGateways) ([]*SessionConfig, error) {

	if sessionPolicies == nil {
		return nil, nil
	}

	var sessID uint8 = 0
	var result []*SessionConfig
	// iterate over IAs in sorted manner, this is not strictly required but it
	// facilitates testing and should create more stable session IDs.
	for _, sessionPolicy := range sessionPolicies {
		gateways, ok := remoteGateways.Gateways[sessionPolicy.IA]
		// It might be that dynamic updates for this IA haven't come in yet, so
		// we ignore this IA.
		if !ok {
			continue
		}
		for _, entry := range gateways {
			pathPol := PathPolicyWithAllowedInterfaces(
				sessionPolicy.PathPolicy,
				sessionPolicy.IA,
				entry.Gateway.Interfaces,
			)
			result = append(result, &SessionConfig{
				ID:             sessID,
				PolicyID:       sessionPolicy.ID,
				IA:             sessionPolicy.IA,
				TrafficMatcher: sessionPolicy.TrafficMatcher,
				PerfPolicy:     sessionPolicy.PerfPolicy,
				PathPolicy:     pathPol,
				PathCount:      sessionPolicy.PathCount,
				Gateway:        entry.Gateway,
				Prefixes:       mergePrefixes(sessionPolicy.Prefixes, entry.Prefixes),
			})
			sessID++
		}
	}
	return result, nil
}

// PathPolicyWithAllowedInterfaces constructs a path policy that only accepts
// path that match the policy and that enter the remote AS on one of the
// allowed interfaces. An empty list of allowed interfaces indicates that
// all interfaces are permitted.
func PathPolicyWithAllowedInterfaces(
	policy policies.PathPolicy,
	remote addr.IA,
	allowedInterfaces []uint64,
) policies.PathPolicy {

	if len(allowedInterfaces) == 0 {
		return policy
	}
	dynPol := newPathPolForEnteringAS(remote, allowedInterfaces)
	if policy == DefaultPathPolicy {
		return dynPol
	}
	return conjuctionPathPol{Pol1: policy, Pol2: dynPol}
}

func mergePrefixes(static, dynamic []*net.IPNet) []*net.IPNet {
	var result []*net.IPNet
	seenNets := make(map[string]struct{}, len(static)+len(dynamic))
	addNets := func(nets []*net.IPNet) {
		for _, n := range nets {
			if _, ok := seenNets[n.String()]; ok {
				continue
			}
			seenNets[n.String()] = struct{}{}
			result = append(result, n)
		}
	}
	addNets(static)
	addNets(dynamic)
	return result
}

type conjuctionPathPol struct {
	Pol1, Pol2 policies.PathPolicy
}

func (p conjuctionPathPol) Filter(s []snet.Path) []snet.Path {
	return p.Pol2.Filter(p.Pol1.Filter(s))
}

func newPathPolForEnteringAS(ia addr.IA, allowedInterfaces []uint64) policies.PathPolicy {
	if len(allowedInterfaces) == 0 {
		return DefaultPathPolicy
	}
	lastHops := make([]string, 0, len(allowedInterfaces))
	for _, intf := range allowedInterfaces {
		lastHops = append(lastHops, fmt.Sprintf("%s#%d", ia, intf))
	}
	rawSeq := fmt.Sprintf("0* (%s)", strings.Join(lastHops, "|"))
	seq, err := pathpol.NewSequence(rawSeq)
	if err != nil {
		panic("invalid sequence: " + rawSeq)
	}
	return &pathpol.Policy{Sequence: seq}
}

func prefixesKey(prefixes []*net.IPNet) string {
	keyParts := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		keyParts = append(keyParts, p.String())
	}
	sort.Strings(keyParts)
	return strings.Join(keyParts, "-")
}
