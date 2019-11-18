// Copyright 2018 Anapaya Systems
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

// Package discovery provides library support to query the discovery
// service for topology files.
//
// The discovery service serves topology files for its own AS. Clients can
// use it to fetch an initial topology file, or to update their topology.
// The topology files are served in two different modes and two different
// privilege versions. Non privileged entities should only get the
// necessary information of the topology.
//
// Modes
//
// Static: The topology file in static mode is updated infrequently. It
// contains a subset of all available service instances which have stable
// addresses and availability.
//
// Dynamic: The topology file in dynamic mode is updated frequently. Service
// instances are dynamically added and removed based on their status. This
// allows ASes to dynamically start and stop instances.
//
// Files
//
// There are two privilege versions of the topology file. The endhost version
// is intended for end hosts and non-privileged entities. The full version is
// only intended for privileged entities that need all topology information.
//
// Endhost: The endhost version of the topology file contains all the
// information necessary for end hosts. Unnecessary information is stripped
// from the file (e.g. border router interface addresses or beacon service
// addresses).
//
// Full: The full version of the topology file contains all the information.
// This file is only accessible by privileged entities (e.g infrastructure
// elements).
//
// Default: When the default version of the topology file is requested, the
// discovery service decides which version to serve based on the privilege
// of the requester.
//
// Paths
//
// The topology files are fetched with a simple http get request. The path
// is dependent on the mode and file version:
//  static  && default:  /discovery/v1/static/default.json
//  static  && endhost:  /discovery/v1/static/endhost.json
//  static  && full:     /discovery/v1/static/full.json
//  dynamic && default:  /discovery/v1/dynamic/default.json
//  dynamic && endhost:  /discovery/v1/dynamic/endhost.json
//  dynamic && full:     /discovery/v1/dynamic/full.json
package discovery

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"golang.org/x/net/context/ctxhttp"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/topology"
)

// FetchParams contains the parameters for fetching the topology from
// the discovery service.
type FetchParams struct {
	// Mode indicates whether the static or the dynamic topology is requested.
	Mode Mode
	// File indicates whether the full, endhost or default topology is requested.
	File File
	// Https indicates whether https should be used.
	Https bool
}

type Mode string

const (
	// Dynamic indicates the dynamic mode.
	Dynamic Mode = "dynamic"
	// Static indicates the static mode.
	Static Mode = "static"
)

type File string

const (
	// Full is the full topology file, including all service information.
	Full File = "full.json"
	// Endhost is a stripped down topology file for non-privileged entities.
	Endhost File = "endhost.json"
	// Default is a topology file whose content is based on the privilege of
	// the requester.
	Default File = "default.json"
)

const (
	// Base is the base path for the topology file url. It is supposed to be used
	// as Base/<mode>/<file>. For example, the dynamic and full topology has the url
	// "discovery/v1/dynamic/full.json"
	Base = "discovery/v1"
)

// FetchTopoRaw fetches the topology with the specified parameters from the
// discovery service. If client is nil, the default http client is used.
// Both the topology and the raw response body are returned.
func FetchTopoRaw(ctx context.Context, params FetchParams, ds *net.UDPAddr,
	client *http.Client) (*topology.Topo, common.RawBytes, error) {

	url, err := createURL(params, ds)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to create URL", err)
	}
	rep, err := ctxhttp.Get(ctx, client, url)
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
	topo, err := topology.Load(raw)
	if err != nil {
		return nil, nil, common.NewBasicError("Unable to parse topo", err)
	}
	return topo, raw, nil
}

// createURL builds the url to the topology file.
func createURL(params FetchParams, ds *net.UDPAddr) (string, error) {
	if ds == nil {
		return "", serrors.New("Addr not set")
	}
	protocol := "http"
	if params.Https {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d/%s", protocol, ds.IP, ds.Port,
		Path(params.Mode, params.File)), nil
}

// Path creates the route to the topology file based on the mode and file.
func Path(mode Mode, file File) string {
	return fmt.Sprintf("%s/%s/%s", Base, mode, file)
}
