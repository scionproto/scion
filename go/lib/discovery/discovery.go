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

const (
	// Base is the base route for the topology file url. It is supposed to be used
	// as Base/<mode>/<file>. For example, the dynamic and full topology has the url
	// "discovery/v1/dynamic/full.json"
	Base = "discovery/v1"
	// Dynamic indicates the dynamic mode.
	Dynamic = "dynamic"
	// Static indicates the static mode.
	Static = "static"
	// Full is the full topology file, including all service information.
	Full = "full.json"
	// Reduced is a stripped down topology file for non-privileged entities.
	Reduced = "reduced.json"
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

// URL builds the url to the topology file.
func URL(addr *addr.AppAddr, dynamic, full, https bool) string {
	url := fmt.Sprintf("%s:%d/%s", addr.L3.IP(), addr.L4.Port(), Route(dynamic, full))
	if https {
		return "https://" + url
	}
	return "http://" + url
}

// Route creates the route to the topology file based on the mode and file.
func Route(dynamic, full bool) string {
	return fmt.Sprintf("%s/%s/%s", Base, mode(dynamic), file(full))
}

func mode(dynamic bool) string {
	if dynamic {
		return Dynamic
	}
	return Static
}

func file(full bool) string {
	if full {
		return Full
	}
	return Reduced
}
