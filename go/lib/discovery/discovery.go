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

package discovery

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/net/context/ctxhttp"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

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
	// Reduced is a stripped down topology file for non-privileged entities.
	Reduced File = "reduced.json"
)

const (
	// Base is the base route for the topology file url. It is supposed to be used
	// as Base/<mode>/<file>. For example, the dynamic and full topology has the url
	// "discovery/v1/dynamic/full.json"
	Base = "discovery/v1"
)

// Topo fetches the topology from the specified url. If client is nil,
// the default http client is used.
func Topo(ctx context.Context, client *http.Client, url string) (*topology.Topo, error) {
	topo, _, err := TopoRaw(ctx, client, url)
	return topo, err
}

// TopoRaw fetches the topology from the specified url. If client is nil,
// the default http client is used. Both the topology and the raw response
// body are returned.
func TopoRaw(ctx context.Context, client *http.Client,
	url string) (*topology.Topo, common.RawBytes, error) {

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

// CreateURL builds the url to the topology file.
func CreateURL(addr *addr.AppAddr, mode Mode, file File, https bool) string {
	protocol := "http"
	if https {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d/%s", protocol, addr.L3.IP(), addr.L4.Port(), Path(mode, file))
}

// Path creates the route to the topology file based on the mode and file.
func Path(mode Mode, file File) string {
	return fmt.Sprintf("%s/%s/%s", Base, mode, file)
}
