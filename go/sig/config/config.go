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

package config

import (
	"encoding/json"
	"io/ioutil"
	"net"

	//log "github.com/inconshreveable/log15"

	"github.com/netsec-ethz/scion/go/lib/common"
)

type SIGCfg struct {
	ASTable map[string]*ASEntry
}

func LoadFromFile(path string) (*SIGCfg, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewCError("Unable to open SIG config", "err", err)
	}
	return Load(b)
}

func Load(b common.RawBytes) (*SIGCfg, error) {
	cfg := &SIGCfg{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, common.NewCError("Unable to parse SIG config", "err", err)
	}
	return cfg, nil
}

type ASEntry struct {
	Nets []*IPNet
	Sigs map[string]*SIGEntry
}

type IPNet net.IPNet

func (in *IPNet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return common.NewCError("Unable to unmarshal IPnet from JSON", "raw", b, "err", err)
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return common.NewCError("Unable to parse IPnet string", "raw", s, "err", err)
	}
	*in = IPNet(*ipnet)
	return nil
}

func (in *IPNet) IPNet() *net.IPNet {
	return (*net.IPNet)(in)
}

type SIGEntry struct {
	Id        string
	Addr      net.IP
	CtrlPort  uint16
	EncapPort uint16
}
