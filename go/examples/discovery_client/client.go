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
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/discovery"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic"
	"github.com/scionproto/scion/go/lib/snet"
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

	ds snet.Addr
)

func init() {
	flag.Var((*snet.Addr)(&ds), "addr", "Discovery service to query for initial topology")
}

func main() {
	os.Setenv("TZ", "UTC")
	log.AddLogConsFlags()
	flag.Parse()
	if *topoPath == "" && ds.Host == nil {
		fmt.Fprintln(os.Stderr, "err: topo and host not specified")
		flag.Usage()
		os.Exit(1)
	}
	defer log.LogPanicAndExit()
	topo, err := getTopo()
	if err != nil {
		log.Crit("Unable to load topology", "err", err)
		os.Exit(1)
	}
	pool, err := discovery.NewPool(topo)
	if err != nil {
		log.Crit("Unable to create discovery service pool", "err", err)
		os.Exit(1)
	}
	log.Info("Discovery pool initialized", "size", len(pool))
	var writeOnce sync.Once
	fetcher := &discovery.Fetcher{
		Pool:    pool,
		Https:   *https,
		Full:    *full,
		Dynamic: *dynamic,
		ErrorF: func(err error) {
			log.Error("Unable to fetch topology", "err", err)
		},
		UpdateF: func(topo *topology.Topo) {
			log.Info("Fetched new topology", "ia", topo.ISD_AS, "ts", topo.Timestamp)
		},
		RawF: func(raw common.RawBytes) {
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
	}
	log.Info("Starting periodic task", "period", *period)
	ticker := time.NewTicker(*period)
	runner := periodic.StartPeriodicTask(fetcher, ticker, *timeout)
	defer runner.Stop()
	select {}

}

func getTopo() (*topology.Topo, error) {
	if ds.Host != nil {
		if *topoPath != "" {
			log.Info("Both topo and addr specified.")
		}
		log.Info("Fetch initial topology from discovery service", "addr", ds.Host)
		ctx, cancelF := context.WithTimeout(context.Background(), *timeout)
		defer cancelF()
		return discovery.Topo(ctx, nil, discovery.URL(ds.Host, *dynamic, *full, *https))
	}
	log.Info("Load initial topology from disk")
	return topology.LoadFromFile(*topoPath)
}
