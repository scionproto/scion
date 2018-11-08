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
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/spath"
)

var (
	dstIAStr     = flag.String("dstIA", "", "Destination IA address: ISD-AS")
	srcIAStr     = flag.String("srcIA", "", "Source IA address: ISD-AS")
	sciondPath   = flag.String("sciond", "", "SCIOND socket path")
	timeout      = flag.Duration("timeout", 5*time.Second, "Timeout in seconds")
	maxPaths     = flag.Int("maxpaths", 10, "Maximum number of paths")
	sciondFromIA = flag.Bool("sciondFromIA", false, "SCIOND socket path from IA address:ISD-AS")
	expiration   = flag.Bool("expiration", false, "Show path expiration timestamps")
	refresh      = flag.Bool("refresh", false, "Set refresh flag for SCIOND path request")
	Local        snet.Addr
)

var (
	dstIA addr.IA
	srcIA addr.IA
)

func main() {
	var err error

	flag.Var((*snet.Addr)(&Local), "local", "Local address to use for health checks")

	log.AddLogConsFlags()
	validateFlags()

	// Get paths from SCIOND.
	sd := sciond.NewService(*sciondPath)
	sdConn, err := sd.ConnectTimeout(*timeout)
	if err != nil {
		LogFatal("Failed to connect to SCIOND: %v\n", err)
	}
	reply, err := sdConn.Paths(dstIA, srcIA, uint16(*maxPaths),
		sciond.PathReqFlags{Refresh: *refresh})
	if err != nil {
		LogFatal("Failed to retrieve paths from SCIOND: %v\n", err)
	}
	if reply.ErrorCode != sciond.ErrorOk {
		LogFatal("SCIOND unable to retrieve paths: %s\n", reply.ErrorCode)
	}

	// Check whether paths are alive. This is done by sending a packet
	// with invalid address via the path. The border router at the destination
	// is going to reply with SCMP error. Receiving the error means that
	// the path is alive.
	if err = snet.Init(srcIA, "", reliable.DefaultDispPath); err != nil {
		LogFatal("Initializing SNET: %v\n", err)
	}
	snetConn, err := snet.ListenSCION("udp4", &Local)
	if err != nil {
		LogFatal("Listening failed: %v\n", err)
	}
	scionConn := snetConn.(*snet.SCIONConn)
	err = scionConn.SetReadDeadline(time.Now().Add(*timeout))
	if err != nil {
		LogFatal("Cannot set deadline: %v\n", err)
	}
	pathStatuses := make(map[string]bool)
	for _, path := range reply.Entries {
		sPath := spath.New(path.Path.FwdPath)
		if err = sPath.InitOffsets(); err != nil {
			LogFatal("Unable to initialize path: %v\n", err)
		}
		nextHop, err := path.HostInfo.Overlay()
		if err != nil {
			LogFatal("Cannot get overlay info: %v\n", err)
		}
		addr := &snet.Addr{
			IA: dstIA,
			Host: &addr.AppAddr{
				L3: addr.HostSVCFromString("NONE"),
				L4: addr.NewL4UDPInfo(0),
			},
			NextHop: nextHop,
			Path:    sPath,
		}
		fmt.Println("Sending test packet to: ", addr)
		_, err = scionConn.WriteTo([]byte{}, addr)
		if err != nil {
			LogFatal("Cannot sand packet: %v\n", err)
		}
		pathStatuses[string(path.Path.FwdPath)] = false
	}
	for i := len(pathStatuses); i > 0; i-- {
		b := make([]byte, 65536, 65536)
		_, addr, err := scionConn.ReadFromSCION(b)
		if _, ok := err.(*snet.OpError); !ok {
			break
		}
		pathStatuses[string(addr.Path.Raw)] = true
	}

	// Print out the results.
	fmt.Println("Available paths to", dstIA)
	i := 0
	for _, path := range reply.Entries {
		if !pathStatuses[string(path.Path.FwdPath)] {
			continue
		}
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
