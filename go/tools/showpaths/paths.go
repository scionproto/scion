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

// Simple show paths application for SCION.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	liblog "github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
)

var (
	dstIAStr   = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr   = flag.String("srcIA", "", "Source IA address: ISD-AS")
	id         = flag.String("id", "paths", "Element ID")
	sciondPath = flag.String("sciond", "", "SCIOND socket path")
	timeout    = flag.Duration("timeout", 2*time.Second, "SCIOND connection timeout")
	maxPaths   = flag.Int("maxpaths", 10, "Maximum number of paths")
)

var (
	dstIA addr.IA
	srcIA addr.IA
)

func main() {
	var err error

	validateFlags()
	liblog.Setup(*id)
	defer liblog.LogPanicAndExit()
	defer liblog.Flush()

	log.Debug("Connecting to SCIOND", "sciond", *sciondPath, "timeout", *timeout)

	sd := sciond.NewService(*sciondPath)
	sdConn, err := sd.ConnectTimeout(*timeout)
	if err != nil {
		LogFatal("Failed to connect to SCIOND", "err", err)
	}
	reply, err := sdConn.Paths(dstIA, srcIA, uint16(*maxPaths), sciond.PathReqFlags{})
	if err != nil {
		LogFatal("Failed to retrieve paths from SCIOND", "err", err)
	}
	fmt.Println("Available paths to", dstIA)
	i := 0
	for _, path := range reply.Entries {
		fmt.Printf("[%2d] %s\n", i, path.Path.String())
		i++
	}
}

func validateFlags() {
	var err error

	flag.Parse()

	dstIA, err = addr.IAFromString(*dstIAStr)
	if err != nil {
		LogFatal("Unable to parse destination IA:", "err", err)
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
		LogFatal("Unable to parse source IA:", "err", err)
	}
}

func LogFatal(msg string, a ...interface{}) {
	log.Crit(msg, a...)
	liblog.Flush()
	os.Exit(1)
}
