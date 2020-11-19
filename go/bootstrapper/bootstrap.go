// Copyright 2018 ETH Zurich
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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	url2 "net/url"
	"os"
	"path"
	"time"
)

import (
	"github.com/scionproto/scion/go/bootstrapper/hinting"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/topology"
	"golang.org/x/net/context/ctxhttp"
)

const (
	baseURL            = "scion/discovery/v1"
	httpRequestTimeout = 2 * time.Second
	hintsTimeout       = 10 * time.Second
)

var (
	// ipHintsChan is used to inform the bootstrapper about discovered ip hints
	ipHintsChan = make(chan net.IP)
)

func tryBootstrapping() error {
	log.Debug("Cfg", "", cfg)
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return common.NewBasicError("bootstrapper could not get interface", err)
	}
	hintGenerators := []hinting.HintGenerator{
		hinting.NewDHCPHintGenerator(&cfg.DHCP, iface),
		// XXX: DNSSD depends on DHCP, should this be better enforced?
		hinting.NewDNSSDHintGenerator(&cfg.DNSSD),
		hinting.NewMDNSHintGenerator(&cfg.MDNS, iface)}

	for _, g := range hintGenerators {
		go func(g hinting.HintGenerator) {
			defer log.HandlePanic()
			g.Generate(ipHintsChan)
		}(g)
	}

	hintsTimeout := time.After(hintsTimeout)
	log.Info("Waiting for hints ...")
OuterLoop:
	for {
		select {
		case ipAddr := <-ipHintsChan:
			serverAddr := &net.TCPAddr{IP: ipAddr, Port: int(hinting.DiscoveryPort)}
			err := pullTopology(serverAddr)
			if err != nil {
				return err
			}
			err = generateSDConfig(cfg.SDConf)
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
	url := fmt.Sprintf("%s://%s:%d/%s", "http", addr.IP, addr.Port, baseURL+"/topology.json")
	_, err := url2.Parse(url)
	if err != nil {
		return common.NewBasicError("Invalid url: ", err)
	}
	raw, err := fetchTopologyHTTP(url)
	if err != nil {
		return err
	}
	// Check that the topology is valid
	_, err = topology.RWTopologyFromJSONBytes(raw)
	if err != nil {
		return common.NewBasicError("unable to parse RWTopology from JSON bytes", err)
	}
	topologyPath := path.Join(cfg.SCIONFolder, "topology.json")
	err = ioutil.WriteFile(topologyPath, raw, 0644)
	if err != nil {
		return common.NewBasicError("Bootstrapper could not store topology", err)
	}
	return nil
}

func fetchTopologyHTTP(url string) (common.RawBytes, error) {
	log.Info("Fetching topology from " + url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	rep, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, common.NewBasicError("HTTP request failed", err)
	}
	defer func() {
		if err := rep.Body.Close(); err != nil {
			log.Error("Error closing the body of the topology response", "err", err)
		}
	}()
	if rep.StatusCode != http.StatusOK {
		return nil, common.NewBasicError("Status not OK", nil, "status", rep.Status)
	}
	raw, err := ioutil.ReadAll(rep.Body)
	if err != nil {
		return nil, common.NewBasicError("Unable to read body", err)
	}
	return raw, nil
}

func pullTRCs(addr *net.TCPAddr) error {
	url := fmt.Sprintf("%s://%s:%d/%s", "http", addr.IP, addr.Port, baseURL+"/trcs.tar.gz")
	log.Info("Fetching TRCs", "url", url)
	ctx, cancelF := context.WithTimeout(context.Background(), httpRequestTimeout)
	defer cancelF()
	rep, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return common.NewBasicError("HTTP request failed", err)
	}
	defer func() {
		if err := rep.Body.Close(); err != nil {
			log.Error("Error closing the body of the TRCs response", "err", err)
		}
	}()
	if rep.StatusCode != http.StatusOK {
		return common.NewBasicError("Status not OK", nil, "status", rep.Status)
	}

	// Extract TRCs gzip tar archive
	zr, err := gzip.NewReader(rep.Body)
	if err != nil {
		return common.NewBasicError("Unable to read body as gzip", err)
	}
	tr := tar.NewReader(zr)
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
			log.Info("Extracting TRC", "name", hdr.Name)
			trcPath := path.Join(cfg.SCIONFolder, "certs", hdr.Name)
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
			return fmt.Errorf("TRCs archive must be composed of TRCs only, unknown type found: %c", hdr.Typeflag)
		}
	}
	if err := zr.Close(); err != nil {
		return common.NewBasicError("error closing gunzip reader", err)
	}
	return nil
}

func generateSDConfig(sdConf string) error {
	if sdConf == "" {
		return nil
	}
	srcConfFile, err := os.OpenFile(sdConf, os.O_RDONLY, 0644)
	if err != nil {
		return common.NewBasicError("error opening src sd conf file", err)
	}
	dstConfFile, err := os.OpenFile(path.Join(cfg.SCIONFolder, "sd.toml"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return common.NewBasicError("error opening dest sd conf file", err)
	}
	_, err = io.Copy(dstConfFile, srcConfFile)
	if err != nil {
		return common.NewBasicError("error copying sd conf file", err)
	}
	return nil
}
