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
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/keyconf"
	"github.com/scionproto/scion/private/topology"
)

// Config stores the runtime configuration state of an ISD-AS context.
type Config struct {
	// Topo contains the names of all local infrastructure elements, a map
	// of interface IDs to routers, and the actual topology.
	Topo topology.Topology
	// IA is the current ISD-AS.
	IA addr.IA
	// BR is the topology information of this router.
	BR *topology.BRInfo
	// MasterKeys holds the local AS master keys.
	MasterKeys keyconf.Master
}

// LoadConfig sets up the configuration, loading it from the supplied config directory.
func LoadConfig(id, confDir string) (*Config, error) {
	conf := &Config{}
	if err := conf.loadTopo(id, confDir); err != nil {
		return nil, err
	}
	if err := conf.loadMasterKeys(confDir); err != nil {
		return nil, err
	}
	return conf, nil
}

// NewConfig sets up the configuration for the given topology,
// loading the keys from the supplied config directory.
func NewConfig(id string, topo topology.Topology, confDir string) (*Config, error) {
	conf := &Config{}
	if err := conf.initTopo(id, topo); err != nil {
		return nil, serrors.Wrap("initializing topology", err)
	}
	if err := conf.loadMasterKeys(confDir); err != nil {
		return nil, err
	}
	return conf, nil
}

func (cfg *Config) String() string {
	return fmt.Sprintf("{IA: %s, BR.Name: %s", cfg.IA, cfg.BR.Name)
}

// loadTopo loads the topology from the config directory and initializes the
// entries related to topo in the config.
func (cfg *Config) loadTopo(id string, confDir string) error {
	topoPath := filepath.Join(confDir, "topology.json")
	topo, err := topology.FromJSONFile(topoPath)
	if err != nil {
		return err
	}
	if err := cfg.initTopo(id, topo); err != nil {
		return serrors.Wrap("initializing topology", err, "file", topoPath)
	}
	return nil
}

// initTopo initializes the entries related to topo in the config.
func (cfg *Config) initTopo(id string, topo topology.Topology) error {
	cfg.Topo = topo
	cfg.IA = cfg.Topo.IA()
	// Find the config for this router.
	topoBR, ok := cfg.Topo.BR(id)
	if !ok {
		return serrors.New("element ID not found", "id", id)
	}
	cfg.BR = &topoBR
	return nil
}

// loadMasterKeys loads the master keys from the config directory.
func (cfg *Config) loadMasterKeys(confDir string) error {
	var err error
	cfg.MasterKeys, err = keyconf.LoadMaster(filepath.Join(confDir, "keys"))
	if err != nil {
		return serrors.Wrap("loading master keys", err)
	}
	return nil
}

// IACtx is the context for the router for a given IA.
type IACtx struct {
	// Config is the router topology configuration
	Config *Config
	// DP is the underlying data plane.
	DP Dataplane

	// ifs and svcs are what DP is configured with.
	ifs  map[iface.ID]externalInterface
	svcs map[service]struct{}
}

// Configure configures the dataplane for the given context.
func (iac *IACtx) Configure() error {
	cfg := iac.Config
	if cfg == nil {
		// Nothing to do
		return serrors.New("empty configuration")
	}

	log.Debug("Configuring Dataplane")
	if err := ConfigDataplane(iac.DP, cfg); err != nil {
		brConfDump, errDump := dumpConfig(cfg)
		if errDump != nil {
			brConfDump = errDump.Error()
		}
		return serrors.Wrap("config setup", err, "config", brConfDump)
	}
	iac.ifs = make(map[iface.ID]externalInterface)
	if cfg.BR != nil {
		ifs, err := externalInterfaces(cfg)
		if err != nil {
			return err
		}
		iac.ifs = ifs
	}
	iac.svcs = make(map[service]struct{})
	for _, s := range services(cfg) {
		iac.svcs[s] = struct{}{}
	}
	log.Debug("Dataplane configured successfully", "config", cfg)
	return nil
}

// NewValidator returns a validator for the topology of router id, configured on dp.
// Besides the checks of [topology.RouterValidator], it rejects topologies
// whose interfaces dp can't have. [IACtx.UpdateTopology] would remove
// a changed interface and then fail to add it again.
func NewValidator(id string, dp Dataplane) topology.Validator {
	return &validator{RouterValidator: topology.RouterValidator{ID: id}, dp: dp}
}

type validator struct {
	topology.RouterValidator
	dp Dataplane
}

func (v *validator) Validate(topo, old *topology.RWTopology) error {
	if err := v.RouterValidator.Validate(topo, old); err != nil {
		return err
	}
	cfg := &Config{}
	if err := cfg.initTopo(v.ID, topology.FromRWTopology(topo)); err != nil {
		return err
	}
	ifs, err := externalInterfaces(cfg)
	if err != nil {
		return err
	}
	if err := checkRemotes(ifs); err != nil {
		return err
	}
	links := make([]LinkInfo, 0, len(ifs))
	for _, x := range ifs {
		links = append(links, x.link)
	}
	return v.dp.CheckExternalInterfaces(links)
}

// checkRemotes returns an error if two interfaces of this router have the same underlay
// and remote address. The underlay couldn't tell their links apart.
func checkRemotes(ifs map[iface.ID]externalInterface) error {
	type key struct {
		provider string
		remote   netip.AddrPort
	}
	seen := make(map[key]iface.ID)
	for _, ifID := range slices.Sorted(maps.Keys(ifs)) {
		x := ifs[ifID]
		if !x.owned {
			// Links to a sibling router are shared by design.
			continue
		}
		remote, err := netip.ParseAddrPort(x.link.Remote.Addr)
		if err != nil {
			return serrors.Wrap("unparsable remote address", err)
		}
		k := key{provider: x.link.Provider, remote: remote}
		if other, ok := seen[k]; ok {
			return serrors.New("interfaces have the same remote address",
				"if_id", other, "other_if_id", ifID, "remote", remote)
		}
		seen[k] = ifID
	}
	return nil
}

// sameLinks reports whether a and b differ at most in what links don't use.
// A new link would interrupt the interface, and a new BFD session starts down.
func sameLinks(a, b externalInterface) bool {
	a.link.MTU, b.link.MTU = 0, 0
	a.link.Remote.IfID, b.link.Remote.IfID = 0, 0
	return reflect.DeepEqual(a, b)
}

// UpdateTopology reconfigures the dataplane for topo, a new version of the topology.
// It adds, removes, and replaces interfaces, and updates the service addresses.
// Interfaces that don't change keep running.
//
// Check topo with [NewValidator] first.
// UpdateTopology applies what it can and returns the errors.
// A later call retries what failed.
func (iac *IACtx) UpdateTopology(topo topology.Topology) error {
	cfg := &Config{MasterKeys: iac.Config.MasterKeys}
	if err := cfg.initTopo(iac.Config.BR.Name, topo); err != nil {
		return err
	}
	if cfg.IA != iac.Config.IA {
		return serrors.New("ISD-AS must not change", "old", iac.Config.IA, "new", cfg.IA)
	}
	if cfg.BR.InternalAddr != iac.Config.BR.InternalAddr {
		return serrors.New("internal address must not change",
			"old", iac.Config.BR.InternalAddr, "new", cfg.BR.InternalAddr)
	}
	want, err := externalInterfaces(cfg)
	if err != nil {
		return err
	}

	var errs serrors.List
	// Remove before adding: a changed interface is removed and added again,
	// and an added interface may take the address of a removed one.
	for _, ifID := range slices.Sorted(maps.Keys(iac.ifs)) {
		cur := iac.ifs[ifID]
		x, ok := want[ifID]
		if ok && reflect.DeepEqual(x, cur) {
			continue
		}
		if ok && sameLinks(x, cur) {
			log.Info("Updating interface", "if_id", ifID)
			if err := iac.DP.UpdateExternalInterface(ifID, x.link); err != nil {
				errs = append(errs, serrors.Wrap("updating interface", err, "if_id", ifID))
				continue
			}
			iac.ifs[ifID] = x
			continue
		}
		log.Info("Removing interface", "if_id", ifID)
		if err := iac.DP.DelExternalInterface(ifID); err != nil {
			errs = append(errs, serrors.Wrap("removing interface", err, "if_id", ifID))
			continue
		}
		delete(iac.ifs, ifID)
	}
	for _, ifID := range slices.Sorted(maps.Keys(want)) {
		if _, ok := iac.ifs[ifID]; ok {
			continue
		}
		x := want[ifID]
		log.Info("Adding interface", "if_id", ifID)
		if err := iac.DP.AddExternalInterface(
			ifID, x.link, x.localHost, x.remoteHost, x.owned); err != nil {
			errs = append(errs, serrors.Wrap("adding interface", err, "if_id", ifID))
			continue
		}
		iac.ifs[ifID] = x
	}

	// Add before removing, so that a service
	// doesn't lose all its addresses while it moves.
	wantSvcs := services(cfg)
	for _, s := range wantSvcs {
		if _, ok := iac.svcs[s]; ok {
			continue
		}
		log.Info("Adding service address", "svc", s.svc, "addr", s.host, "port", s.port)
		if err := iac.DP.AddSvc(cfg.IA, s.svc, s.host, s.port); err != nil {
			errs = append(errs, serrors.Wrap("adding service address", err,
				"svc", s.svc, "addr", s.host, "port", s.port))
			continue
		}
		iac.svcs[s] = struct{}{}
	}
	for s := range iac.svcs {
		if slices.Contains(wantSvcs, s) {
			continue
		}
		log.Info("Removing service address",
			"svc", s.svc,
			"addr", s.host,
			"port", s.port)
		if err := iac.DP.DelSvc(cfg.IA, s.svc, s.host, s.port); err != nil {
			errs = append(errs, serrors.Wrap("removing service address", err,
				"svc", s.svc, "addr", s.host, "port", s.port))
			continue
		}
		delete(iac.svcs, s)
	}

	iac.Config = cfg
	return errs.ToError()
}

func dumpConfig(cfg *Config) (string, error) {
	if cfg == nil {
		return "", serrors.New("empty configuration")
	}
	b, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
