// Copyright 2026 Anapaya Systems
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

// Package prism renders the generalized SCION configuration model into the
// service-specific files (router, control, daemon, gateway).
package prism

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/pelletier/go-toml/v2"

	controlconfig "github.com/scionproto/scion/control/config"
	daemonconfig "github.com/scionproto/scion/daemon/config"
	dispatcherconfig "github.com/scionproto/scion/dispatcher/config"
	gatewayconfig "github.com/scionproto/scion/gateway/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/env"
	mgmtapi "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/storage"
	routerconfig "github.com/scionproto/scion/router/config"
	clabconfig "github.com/scionproto/scion/testing/clab/cmd/controller/config"
)

// configDir is the in-container directory holding the topology, certs and keys.
const configDir = "/etc/scion"

// dbDir is the in-container directory holding the service databases.
const dbDir = "/var/lib/scion"

// logLevel is the console log level baked into generated configs.
const logLevel = "debug"

// ServiceFile is a single generated service configuration file. Binary is the
// name of the SCION service executable that consumes it (e.g. "router",
// "control", "dispatcher", "daemon", "gateway"), so a caller can both write the
// file and launch the process that runs it.
type ServiceFile struct {
	Name    string
	Binary  string
	Content []byte
	// Env holds additional environment variables ("KEY=value") for the service
	// process.
	Env []string
	// Aux are additional files the service reads (e.g. the gateway's traffic
	// policy). They are written next to the service file, into configDir.
	Aux []AuxFile
}

// AuxFile is an additional file referenced by a service configuration.
type AuxFile struct {
	Name    string
	Content []byte
}

// Service binary names, matching the executables shipped in the clab node image.
const (
	binRouter     = "router"
	binControl    = "control"
	binDispatcher = "dispatcher"
	binDaemon     = "daemon"
	binGateway    = "gateway"
)

// gatewayPathUpdateInterval speeds up the gateway's path updates (default:
// minutes), so that a freshly started gateway establishes its sessions quickly.
const gatewayPathUpdateInterval = "SCION_EXPERIMENTAL_GATEWAY_PATH_UPDATE_INTERVAL=1s"

// Render produces the service configuration file(s) for the elements present
// in cfg (the host's local elements). It does not produce topology.json, which
// is an AS-wide artifact generated separately.
func Render(cfg clabconfig.Config) ([]ServiceFile, error) {
	var files []ServiceFile
	for _, as := range cfg.SCION.ASes {
		if as.Router != nil {
			f, err := renderRouter(as.Router)
			if err != nil {
				return nil, serrors.Wrap("rendering router", err, "id", as.Router.ID)
			}
			files = append(files, f)
		}
		if as.Control != nil {
			f, err := renderControl(as.Control)
			if err != nil {
				return nil, serrors.Wrap("rendering control", err, "id", as.Control.ID)
			}
			files = append(files, f)
			// The shim dispatcher is co-located with the control service: it
			// receives SVC (CS/DS) traffic on the well-known port and forwards
			// it to the local control service.
			d, err := renderDispatcher(as.ISDAS, as.Control)
			if err != nil {
				return nil, serrors.Wrap("rendering dispatcher", err, "id", as.Control.ID)
			}
			files = append(files, d)
		}
		if as.Daemon != nil {
			f, err := renderDaemon(as.Daemon)
			if err != nil {
				return nil, serrors.Wrap("rendering daemon", err, "id", as.Daemon.ID)
			}
			files = append(files, f)
		}
		if as.Gateway != nil {
			f, err := renderGateway(as.Gateway)
			if err != nil {
				return nil, serrors.Wrap("rendering gateway", err, "id", as.Gateway.ID)
			}
			files = append(files, f)
		}
	}
	return files, nil
}

func renderRouter(r *clabconfig.Router) (ServiceFile, error) {
	cfg := routerconfig.Config{
		General: env.General{ID: r.ID, ConfigDir: configDir},
		Logging: consoleLog(),
		API:     mgmtapi.Config{Addr: addrString(r.APIAddr)},
	}
	return marshal(r.ID+".toml", binRouter, cfg)
}

func renderControl(c *clabconfig.Control) (ServiceFile, error) {
	mode := controlconfig.Disabled
	if c.Issuing {
		mode = controlconfig.InProcess
	}
	cfg := controlconfig.Config{
		General:  env.General{ID: c.ID, ConfigDir: configDir},
		Logging:  consoleLog(),
		API:      mgmtapi.Config{Addr: addrString(c.APIAddr)},
		TrustDB:  db(c.ID, "trust"),
		BeaconDB: db(c.ID, "beacon"),
		PathDB:   db(c.ID, "path"),
		CA:       controlconfig.CA{Mode: mode},
	}
	return marshal(c.ID+".toml", binControl, cfg)
}

func renderDispatcher(ia addr.IA, c *clabconfig.Control) (ServiceFile, error) {
	id := "disp_" + c.ID
	cfg := dispatcherconfig.Config{
		Logging: consoleLog(),
		Dispatcher: dispatcherconfig.Dispatcher{
			ID:                 id,
			LocalUDPForwarding: true,
			// UnderlayAddr is left unset: the shim then listens on :: (all
			// interfaces), so SVC traffic forwarded by remote border routers
			// over the management network is received.
			ServiceAddresses: map[addr.Addr]netip.AddrPort{
				{IA: ia, Host: addr.HostSVC(addr.SvcCS)}: c.Address,
				{IA: ia, Host: addr.HostSVC(addr.SvcDS)}: c.Address,
			},
		},
	}
	return marshal(id+".toml", binDispatcher, cfg)
}

func renderDaemon(d *clabconfig.Daemon) (ServiceFile, error) {
	cfg := daemonconfig.Config{
		General: env.General{ID: d.ID, ConfigDir: configDir},
		Logging: consoleLog(),
		API:     mgmtapi.Config{Addr: addrString(d.APIAddr)},
		TrustDB: db(d.ID, "trust"),
		PathDB:  db(d.ID, "path"),
		SD:      daemonconfig.SDConfig{Address: addrString(d.Address)},
	}
	return marshal(d.ID+".toml", binDaemon, cfg)
}

// renderGateway renders the gateway configuration and its traffic policy. The
// traffic policy uses the legacy format, which maps each remote AS to the IP
// prefixes routed to it.
func renderGateway(g *clabconfig.Gateway) (ServiceFile, error) {
	policyName := g.ID + ".traffic.json"
	cfg := gatewayconfig.Config{
		Logging: consoleLog(),
		API:     mgmtapi.Config{Addr: addrString(g.APIAddr)},
		Daemon:  env.Daemon{Address: addrString(g.Daemon)},
		Gateway: gatewayconfig.Gateway{
			ID:            g.ID,
			TrafficPolicy: configDir + "/" + policyName,
			CtrlAddr:      addrString(g.CtrlAddr),
			DataAddr:      addrString(g.DataAddr),
			ProbeAddr:     addrString(g.ProbeAddr),
		},
	}
	if g.TunnelSrcV4.IsValid() {
		cfg.Tunnel.SrcIPv4 = net.IP(g.TunnelSrcV4.AsSlice())
	}
	f, err := marshal(g.ID+".toml", binGateway, cfg)
	if err != nil {
		return ServiceFile{}, err
	}

	type remoteAS struct {
		Nets []string `json:"Nets"`
	}
	policy := struct {
		ConfigVersion int                 `json:"ConfigVersion"`
		ASes          map[string]remoteAS `json:"ASes"`
	}{ConfigVersion: 1, ASes: map[string]remoteAS{}}
	for _, r := range g.Remotes {
		nets := make([]string, 0, len(r.Prefixes))
		for _, p := range r.Prefixes {
			nets = append(nets, p.String())
		}
		policy.ASes[r.ISDAS.String()] = remoteAS{Nets: nets}
	}
	raw, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return ServiceFile{}, serrors.Wrap("marshaling traffic policy", err)
	}
	f.Env = []string{gatewayPathUpdateInterval}
	f.Aux = []AuxFile{{Name: policyName, Content: append(raw, '\n')}}
	return f, nil
}

func consoleLog() log.Config {
	return log.Config{Console: log.ConsoleConfig{Level: logLevel}}
}

func db(id, kind string) storage.DBConfig {
	return storage.DBConfig{Connection: fmt.Sprintf("%s/%s.%s.db", dbDir, id, kind)}
}

func addrString(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return ""
	}
	return ap.String()
}

func marshal(name, binary string, v any) (ServiceFile, error) {
	raw, err := toml.Marshal(v)
	if err != nil {
		return ServiceFile{}, serrors.Wrap("marshaling TOML", err)
	}
	return ServiceFile{Name: name, Binary: binary, Content: raw}, nil
}
