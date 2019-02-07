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

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/discovery/topofetcher"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/topology"
)

var (
	https    = flag.Bool("https", false, "Use https to connect")
	full     = flag.Bool("full", false, "Request full topology")
	dynamic  = flag.Bool("dynamic", false, "Request dynamic topology")
	topoPath = flag.String("topo", "", "Topology file")
	out      = flag.String("out", "", "Write topology to this file")
	period   = flag.Duration("period", 2*time.Second, "Time between requests")
	timeout  = flag.Duration("timeout", 2*time.Second, "Timeout for single request")
	ds       = flag.String("addr", "", "Discovery service to query for initial topology "+
		"(form \"host:port\" or \"[host]:port\"")
	// FIXME(roosd): Use AppAddr parsing once code base does no longer assume L4 is UDP.
	dsAddr addr.AppAddr
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	os.Setenv("TZ", "UTC")
	log.AddLogConsFlags()
	flag.Parse()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "err: Unable to setup logging err=%s\n", err)
		flag.Usage()
		return 1
	}
	defer log.LogPanicAndExit()
	if err := validateFlags(); err != nil {
		log.Crit("Unable to validate flags", "err", err)
		return 1
	}
	topo, err := getTopo()
	if err != nil {
		log.Crit("Unable to load topology", "err", err)
		return 1
	}
	var writeOnce sync.Once
	fetcher, err := topofetcher.New(
		topo.DS,
		discovery.FetchParams{
			File:  file(),
			Mode:  mode(),
			Https: *https,
		},
		topofetcher.Callbacks{
			Error: func(err error) {
				log.Error("Unable to fetch topology", "err", err)
			},
			Update: func(topo *topology.Topo) {
				log.Info("Fetched new topology", "ia", topo.ISD_AS, "ts", topo.Timestamp)
			},
			Raw: func(raw common.RawBytes, _ *topology.Topo) {
				writeOnce.Do(func() {
					fmt.Println(string(raw))
					if *out == "" {
						return
					}
					if err := ioutil.WriteFile(*out, raw, 0666); err != nil {
						log.Error("Unable to write topology file", "err", err)
					}
					log.Info("Topology file written", "file", out)
				})
			},
		}, nil)
	if err != nil {
		log.Crit("Unable to initialize fetcher", "err", err)
		return 1
	}
	log.Info("Starting periodic fetching", "period", *period)
	ticker := periodic.NewTicker(*period)
	runner := periodic.StartPeriodicTask(fetcher, ticker, *timeout)
	defer runner.Stop()
	select {}
}

func validateFlags() error {
	if *topoPath == "" && *ds == "" {
		return common.NewBasicError("Topology and discovery service address not specified", nil)
	}
	if *ds != "" && *topoPath != "" {
		return common.NewBasicError("Both topology and discovery service address specified", nil)
	}
	if *ds != "" {
		host, port, err := net.SplitHostPort(*ds)
		if err != nil {
			return common.NewBasicError("Unable to parse discovery service address", err)
		}
		if dsAddr.L3 = addr.HostFromIPStr(host); dsAddr.L3 == nil {
			return common.NewBasicError("Unable to parse host", nil, "host", host)
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			return common.NewBasicError("Unable to parse port", nil, "port", port)
		}
		dsAddr.L4 = addr.NewL4TCPInfo(uint16(p))
	}
	return nil
}

func getTopo() (*topology.Topo, error) {
	if *ds != "" {
		log.Info("Fetch initial topology from discovery service", "addr", ds)
		ctx, cancelF := context.WithTimeout(context.Background(), *timeout)
		defer cancelF()
		return discovery.FetchTopo(ctx, discovery.FetchParams{
			File:  file(),
			Mode:  mode(),
			Https: *https,
		}, &dsAddr, nil)
	}
	log.Info("Load initial topology from disk", "topo", topoPath)
	return topology.LoadFromFile(*topoPath)
}

func mode() discovery.Mode {
	if *dynamic {
		return discovery.Dynamic
	}
	return discovery.Static
}

func file() discovery.File {
	if *full {
		return discovery.Full
	}
	return discovery.Reduced
}
