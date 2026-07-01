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

package prism

import (
	"fmt"
	"net/netip"

	"github.com/pelletier/go-toml/v2"

	controlconfig "github.com/scionproto/scion/control/config"
	daemonconfig "github.com/scionproto/scion/daemon/config"
	dispatcherconfig "github.com/scionproto/scion/dispatcher/config"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/env"
	mgmtapi "github.com/scionproto/scion/private/mgmtapi"
	"github.com/scionproto/scion/private/storage"
	routerconfig "github.com/scionproto/scion/router/config"
)

// configDir is the in-container directory holding the topology, certs and keys.
const configDir = "/etc/scion"

// dbDir is the in-container directory holding the service databases.
const dbDir = "/var/lib/scion"

// logLevel is the console log level baked into generated configs.
const logLevel = "debug"

// ServiceFile is a single generated service configuration file. Binary is the
// name of the SCION service executable that consumes it (e.g. "router",
// "control", "dispatcher", "daemon"), so a caller can both write the file and
// launch the process that runs it.
type ServiceFile struct {
	Name    string
	Binary  string
	Content []byte
}

// Service binary names, matching the executables shipped in the clab node image.
const (
	binRouter     = "router"
	binControl    = "control"
	binDispatcher = "dispatcher"
	binDaemon     = "daemon"
)

// Render produces the service configuration file(s) for the elements present
// in cfg (the host's local elements). It does not produce topology.json, which
// is an AS-wide artifact generated separately.
func Render(cfg Config) ([]ServiceFile, error) {
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
	}
	return files, nil
}

func renderRouter(r *Router) (ServiceFile, error) {
	cfg := routerconfig.Config{
		General: env.General{ID: r.ID, ConfigDir: configDir},
		Logging: consoleLog(),
		API:     mgmtapi.Config{Addr: addrString(r.APIAddr)},
	}
	return marshal(r.ID+".toml", binRouter, cfg)
}

func renderControl(c *Control) (ServiceFile, error) {
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

func renderDispatcher(ia addr.IA, c *Control) (ServiceFile, error) {
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

func renderDaemon(d *Daemon) (ServiceFile, error) {
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
