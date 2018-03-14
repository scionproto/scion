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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/sciond"
)

var (
	dstIAStr   = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr   = flag.String("srcIA", "", "Source IA address: ISD-AS")
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

	sd := sciond.NewService(*sciondPath)
	sdConn, err := sd.ConnectTimeout(*timeout)
	if err != nil {
		LogFatal("Failed to connect to SCIOND: %v\n", err)
	}
	reply, err := sdConn.Paths(dstIA, srcIA, uint16(*maxPaths), sciond.PathReqFlags{})
	if err != nil {
		LogFatal("Failed to retrieve paths from SCIOND: %v\n", err)
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
		LogFatal("Unable to parse destination IA: %v\n", err)
	}
	if *sciondPath == "" {
		if *srcIAStr == "" {
			*sciondPath = "/run/shm/sciond/default.sock"
		} else {
			*sciondPath = "/run/shm/sciond/sd" + *srcIAStr + ".sock"
		}
	} else if *srcIAStr != "" {
		fmt.Printf("srcIA ignored! sciond takes precedence\n")
	}
	if *srcIAStr == "" {
		// Set any value, required by Query() but does not affect result
		*srcIAStr = "1-10"
	}
	srcIA, err = addr.IAFromString(*srcIAStr)
	if err != nil {
		LogFatal("Unable to parse source IA: %v\n", err)
	}
}

func LogFatal(msg string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, a...)
	os.Exit(1)
}
