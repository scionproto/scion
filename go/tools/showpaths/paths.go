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
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
)

var (
	dstIAStr     = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr     = flag.String("srcIA", "", "Source IA address: ISD-AS")
	sciondPath   = flag.String("sciond", "", "SCIOND socket path")
	timeout      = flag.Duration("timeout", 2*time.Second, "SCIOND connection timeout")
	maxPaths     = flag.Int("maxpaths", 10, "Maximum number of paths")
	sciondFromIA = flag.Bool("sciondFromIA", false, "SCIOND socket path from IA address:ISD-AS")
	expiration   = flag.Bool("expiration", false, "Show path expiration timestamps")
)

var (
	dstIA addr.IA
	srcIA addr.IA
)

func main() {
	var err error

	log.AddLogConsFlags()
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
		if *expiration {
			fmt.Printf("[%2d] %s Expires: %s (%s)\n", i, path.Path.String(), path.Path.Expiry(),
				time.Until(path.Path.Expiry()).Truncate(time.Second))
		} else {
			fmt.Printf("[%2d] %s\n", i, path.Path.String())
		}
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

	if *srcIAStr != "" {
		if srcIA, err = addr.IAFromString(*srcIAStr); err != nil {
			LogFatal("Unable to parse source IA: %v\n", err)
		}
	}

	if *sciondFromIA {
		if *sciondPath != "" {
			LogFatal("Only one of -sciond or -sciondFromIA can be specified")
		}
		if srcIA.IsZero() {
			LogFatal("-srcIA flag is missing")
		}
		*sciondPath = sciond.GetDefaultSCIONDPath(&srcIA)
	} else if *sciondPath == "" {
		*sciondPath = sciond.GetDefaultSCIONDPath(nil)
	}
}

func LogFatal(msg string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, a...)
	os.Exit(1)
}
