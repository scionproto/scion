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

package base

import (
	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/snet"
)

type SIGEntry struct {
	IA          *addr.ISD_AS
	Id          string
	Host        addr.HostAddr
	CtrlL4Port  int
	EncapL4Port int
	Active      bool
	Static      bool // If from local config file true, else from discovery, so false.
}

func NewSIGInfo(ia *addr.ISD_AS, id string, host addr.HostAddr,
	ctrlPort, encapPort int, static bool) *SIGEntry {
	return &SIGEntry{
		IA: ia, Id: id, Host: host, CtrlL4Port: ctrlPort,
		EncapL4Port: encapPort, Active: true, Static: static,
	}
}

func (se *SIGEntry) CtrlSnetAddr() *snet.Addr {
	return &snet.Addr{IA: se.IA, Host: se.Host, L4Port: uint16(se.CtrlL4Port)}
}

func (se *SIGEntry) EncapSnetAddr() *snet.Addr {
	return &snet.Addr{IA: se.IA, Host: se.Host, L4Port: uint16(se.EncapL4Port)}
}

func (se *SIGEntry) Cleanup() error {
	// Nothing to do, currently.
	return nil
}
