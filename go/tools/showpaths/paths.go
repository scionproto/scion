// Copyright 2018 ETH Zurich, Anapaya Systems
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
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
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
	status       = flag.Bool("p", false, "Probe the paths and print out the statuses")
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

	sd := sciond.NewService(*sciondPath, false)
	sdConn, err := sd.ConnectTimeout(*timeout)
	if err != nil {
		LogFatal("Failed to connect to SCIOND: %v\n", err)
	}
	reply, err := sdConn.Paths(context.Background(), dstIA, srcIA, uint16(*maxPaths),
		sciond.PathReqFlags{Refresh: *refresh})
	if err != nil {
		LogFatal("Failed to retrieve paths from SCIOND: %v\n", err)
	}
	if reply.ErrorCode != sciond.ErrorOk {
		LogFatal("SCIOND unable to retrieve paths: %s\n", reply.ErrorCode)
	}

	fmt.Println("Available paths to", dstIA)
	var pathStatuses map[string]string
	if *status {
		pathStatuses = getStatuses(reply.Entries)
	}
	for i, path := range reply.Entries {
		fmt.Printf("[%2d] %s", i, path.Path.String())
		if *expiration {
			fmt.Printf(" Expires: %s (%s)", path.Path.Expiry(),
				time.Until(path.Path.Expiry()).Truncate(time.Second))
		}
		if *status {
			fmt.Printf(" Status: %s", pathStatuses[string(path.Path.FwdPath)])
		}
		fmt.Printf("\n")
	}
}

func validateFlags() {
	var err error

	flag.Parse()
	log.SetupFromFlags("")

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

func getStatuses(paths []sciond.PathReplyEntry) map[string]string {
	// Check whether paths are alive. This is done by sending a packet
	// with invalid address via the path. The border router at the destination
	// is going to reply with SCMP error. Receiving the error means that
	// the path is alive.
	if err := snet.Init(srcIA, "", reliable.DefaultDispPath); err != nil {
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
	pathStatuses := make(map[string]string)
	for _, path := range paths {
		sendTestPacket(scionConn, path)
		pathStatuses[string(path.Path.FwdPath)] = "Timeout"
	}
	for i := len(pathStatuses); i > 0; i-- {
		path, status := receiveTestReply(scionConn)
		if path == nil {
			break
		}
		if pathStatuses[*path] != "Timeout" {
			// Two replies received for the same path.
			pathStatuses[*path] = "Unknown"
			continue
		}
		pathStatuses[*path] = status
	}
	return pathStatuses
}

func sendTestPacket(scionConn *snet.SCIONConn, path sciond.PathReplyEntry) {
	sPath := spath.New(path.Path.FwdPath)
	if err := sPath.InitOffsets(); err != nil {
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
	log.Debug("Sending test packet.", "path", path.Path.String())
	_, err = scionConn.WriteTo([]byte{}, addr)
	if err != nil {
		LogFatal("Cannot send packet: %v\n", err)
	}
}

func receiveTestReply(scionConn *snet.SCIONConn) (*string, string) {
	b := make([]byte, 1500, 1500)
	_, addr, err := scionConn.ReadFromSCION(b)
	if addr == nil {
		if basicErr, ok := err.(common.BasicError); ok {
			if netErr, ok := basicErr.Err.(net.Error); ok && netErr.Timeout() {
				// Timeout expired before all replies were received.
				return nil, ""
			}
		}
		if err != nil {
			LogFatal("Cannot read packet: %v\n", err)
		}
		LogFatal("Packet without an address received: %v\n", err)
	}
	path := string(addr.Path.Raw)
	if err == nil {
		// We've got an actual reply instead of SCMP error. This should not happen.
		return &path, "Unknown"
	}
	if opErr, ok := err.(*snet.OpError); ok {
		if opErr.SCMP().Class == scmp.C_Routing && opErr.SCMP().Type == scmp.T_R_BadHost {
			// Expected outcome. The peer complains about SvcNone being an invalid address.
			return &path, "Alive"
		}
	}
	// All other errors are just reported alongside the path.
	return &path, err.Error()
}
