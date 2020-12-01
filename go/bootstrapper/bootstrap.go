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

package main

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"golang.org/x/net/context/ctxhttp"

	"github.com/scionproto/scion/go/bootstrapper/config"
	"github.com/scionproto/scion/go/bootstrapper/hinting"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	baseURL              = "scion/discovery/v1"
	topologyEndpoint     = "/topology.json"
	TRCsEndpoint         = "/trcs.tar"
	TopologyJSONFileName = "topology.json"
	httpRequestTimeout   = 2 * time.Second
	hintsTimeout         = 10 * time.Second
)

type Bootstrapper struct {
	cfg   *config.Config
	iface *net.Interface
	// ipHintsChan is used to inform the bootstrapper about discovered ip hints
	ipHintsChan chan net.IP
}

func NewBootstrapper(cfg *config.Config) (*Bootstrapper, error) {
	log.Debug("Cfg", "", cfg)
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, common.NewBasicError("getting interface by name", err)
	}
	return &Bootstrapper{
		cfg,
		iface,
		make(chan net.IP)}, nil
}

func (b *Bootstrapper) tryBootstrapping() error {
	hintGenerators := []hinting.HintGenerator{
		hinting.NewMockHintGenerator(&cfg.MOCK),
		hinting.NewDHCPHintGenerator(&cfg.DHCP, b.iface),
		// XXX: DNSSD depends on DHCP, should this be better enforced?
		hinting.NewDNSSDHintGenerator(&cfg.DNSSD),
		hinting.NewMDNSHintGenerator(&cfg.MDNS, b.iface)}
	for _, g := range hintGenerators {
		go func(g hinting.HintGenerator) {
			defer log.HandlePanic()
			g.Generate(b.ipHintsChan)
		}(g)
	}
	hintsTimeout := time.After(hintsTimeout)
	log.Info("Waiting for hints ...")
OuterLoop:
	for {
		select {
		case ipAddr := <-b.ipHintsChan:
			serverAddr := &net.TCPAddr{IP: ipAddr, Port: int(hinting.DiscoveryPort)}
			err := pullTopology(serverAddr)
			if err != nil {
				return err
			}
			err = pullTRCs(serverAddr)
			if err != nil {
				return err
			}
			break OuterLoop
		case <-hintsTimeout:
			return fmt.Errorf("bootstrapper timed out")
		}
	}
	return nil
}

func pullTopology(addr *net.TCPAddr) error {
	url := buildTopologyURL(addr.IP, addr.Port)
	log.Info("Fetching topology from " + url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			log.Error("Error closing the body of the topology response", "err", err)
		}
	}()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return common.NewBasicError("Unable to read from response body", err)
	}
	// Check that the topology is valid
	_, err = topology.RWTopologyFromJSONBytes(raw)
	if err != nil {
		return common.NewBasicError("unable to parse RWTopology from JSON bytes", err)
	}
	topologyPath := path.Join(cfg.TopologyFolder, TopologyJSONFileName)
	err = ioutil.WriteFile(topologyPath, raw, 0644)
	if err != nil {
		return common.NewBasicError("Bootstrapper could not store topology", err)
	}
	return nil
}

func buildTopologyURL(ip net.IP, port int) string {
	urlPath := baseURL + topologyEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func pullTRCs(addr *net.TCPAddr) error {
	url := buildTRCsURL(addr.IP, addr.Port)
	log.Info("Fetching TRCs", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	r, err := fetchHTTP(ctx, url)
	if err != nil {
		return err
	}
	// Close response reader and handle errors
	defer func() {
		if err := r.Close(); err != nil {
			log.Error("Error closing the body of the TRCs response", "err", err)
		}
	}()
	// Extract TRCs tar archive
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return common.NewBasicError("error reading tar archive", err)
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
			trcName := filepath.Base(hdr.Name)
			if trcName == "." {
				log.Error("Invalid TRC file name", "name", hdr.Name)
				continue
			}
			log.Info("Extracting TRC", "name", trcName)
			trcPath := path.Join(cfg.TRCsFolder, trcName)
			f, err := os.OpenFile(trcPath, os.O_CREATE|os.O_RDWR, 0644)
			if err != nil {
				return common.NewBasicError("error creating file to store TRC", err)
			}
			_, err = io.Copy(f, tr)
			if err != nil {
				return common.NewBasicError("error writing TRC file", err)
			}
		case tar.TypeDir:
			return fmt.Errorf("TRCs archive must be composed of TRCs only, directory found")
		default:
			return fmt.Errorf("TRCs archive must be composed of TRCs only"+
				", unknown type found: %c", hdr.Typeflag)
		}
	}
	return nil
}

func buildTRCsURL(ip net.IP, port int) string {
	urlPath := baseURL + TRCsEndpoint
	return fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
}

func fetchHTTP(ctx context.Context, url string) (io.ReadCloser, error) {
	res, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, common.NewBasicError("HTTP request failed", err)
	}
	if res.StatusCode != http.StatusOK {
		if err != res.Body.Close() {
			log.Error("Error closing response body", "err", err)
		}
		return nil, common.NewBasicError("Status not OK", nil, "status", res.Status)
	}
	return res.Body, nil
}
