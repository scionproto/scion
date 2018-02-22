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
	"flag"
	"net"
	"regexp"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	id          = flag.String("id", "echo", "Element ID")
	interactive = flag.Bool("i", false, "Interactive mode")
	sciond      = flag.String("sciond", "", "Path to sciond socket")
	dispatcher  = flag.String("dispatcher", "/run/shm/dispatcher/default.sock",
		"Path to dispatcher socket")
	interval = flag.Duration("interval", DefaultInterval, "time between packets")
	count    = flag.Uint("c", 10, "Total number of packet to send (ignored if not echo")
	logLevel = flag.String("logLevel", "info", "Console logging level")
	sTypeStr = &sType
)

var sType string = "echo"

func init() {
	flag.Var((*Address)(&local), "local", "(Mandatory) address to listen on")
	flag.Var((*Address)(&remote), "remote", "(Mandatory for clients) address to connect to")
	flag.Parse()
}

type Address snet.Addr

func (a *Address) String() string {
	return (*snet.Addr)(a).String()
}

func parseAddr(s string) (map[string]string, error) {
	addrRegexp := regexp.MustCompile(`^(?P<ia>\d+-\d+),\[(?P<host>[^\]]+)\]$`)
	result := make(map[string]string)
	match := addrRegexp.FindStringSubmatch(s)
	// If we do not have all submatches (ia, host), return an error
	if len(match) != 3 {
		return nil, common.NewBasicError("Invalid address", nil, "addr", s)
	}
	for i, name := range addrRegexp.SubexpNames() {
		if i != 0 {
			result[name] = match[i]
		}
	}
	return result, nil
}

func (a *Address) Set(s string) error {
	parts, err := parseAddr(s)
	if err != nil {
		return err
	}
	ia, err := addr.IAFromString(parts["ia"])
	if err != nil {
		return common.NewBasicError("Invalid IA string", err, "ia", ia)
	}
	ip := net.ParseIP(parts["host"])
	if ip == nil {
		return common.NewBasicError("Invalid IP address string", nil, "ip", parts["host"])
	}
	a.IA, a.Host = ia, addr.HostFromIP(ip)
	return nil
}
