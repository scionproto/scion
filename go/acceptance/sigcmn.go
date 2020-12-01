// Copyright 2018 ETH Zurich
// Copyright 2020 ETH Zurich, Anapaya Systems
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

package acceptance

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/integration"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	iaIPMap = make(map[addr.IA]net.IP)
)

var SigAddr integration.HostAddr = func(ia addr.IA) *snet.UDPAddr {
	return &snet.UDPAddr{IA: ia, Host: &net.UDPAddr{IP: iaIPMap[ia]}}
}

func ReadTestingConf() error {
	if err := loadNetAlloc(); err != nil {
		return err
	}
	if len(iaIPMap) != 0 {
		return nil
	}
	return loadSigTestingConfig()
}

func loadSigTestingConfig() error {
	conf := integration.GenFile("sig-testing.conf")
	file, err := os.Open(conf)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) == 2 {
			ia, err := addr.IAFromString(parts[0])
			if err != nil {
				return err
			}
			iaIPMap[ia] = net.ParseIP(parts[1])
		} else {
			return serrors.New("Bad line format", "line", line)
		}
	}
	return nil
}

func loadNetAlloc() error {
	nets, err := integration.LoadNetworkAllocs()
	if err != nil {
		return err
	}
	for ia, a := range nets {
		iaIPMap[ia] = a.Host.IP
	}
	return nil
}
