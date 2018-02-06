// Copyright 2017 ETH Zurich
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

// Simple show paths application for SCION.
package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/pathmgr"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	dstIAStr       = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr       = flag.String("srcIA", "", "Source IA address: ISD-AS")
	sciondPath     = flag.String("sciond", "", "SCIOND socket path")
	dispatcherPath = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"SCION Dispatcher path")
)

var (
	dstIA   *addr.ISD_AS
	srcIA   *addr.ISD_AS
	PathMgr *pathmgr.PR
)

func validateFlags() {
	var err error

	flag.Parse()

	dstIA, err = addr.IAFromString(*dstIAStr)
	if err != nil {
		LogFatal("dstIA:", err)
	}

	if *sciondPath == "" {
		if *srcIAStr == "" {
			LogFatal("sciond or srcIA required")
		}

		*sciondPath = "/run/shm/sciond/sd" + *srcIAStr + ".sock"
	} else if *srcIAStr != "" {
		log.Warn("srcIA ignored! sciond takes precedence")
	}

	if *srcIAStr == "" {
		// Set any value, required by Query() but does not affect result
		*srcIAStr = "1-10"
	}
	srcIA, err = addr.IAFromString(*srcIAStr)
	if err != nil {
		LogFatal("srcIA:", err)
	}
}

func main() {
	var err error

	validateFlags()

	log.Debug("Connecting to SCIOND", "sciond", *sciondPath)

	// Initialize SCION local networking module
	err = snet.Init(srcIA, *sciondPath, *dispatcherPath)
	if err != nil {
		LogFatal("Initizaling SCION local networking module", "err", common.FmtError(err))
	}
	PathMgr = snet.DefNetwork.PathResolver()

	pathSet := PathMgr.Query(srcIA, dstIA)
	i := 0
	for _, path := range pathSet {
		fmt.Printf("[%2d] %s\n", i, path.Entry.Path.String())
		i++
	}
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	os.Exit(1)
}
