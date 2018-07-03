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

// Package config is responsible for parsing the SIG json config file into a
// set of simple intermediate data-structures.
package config

import (
	"encoding/json"
	"io/ioutil"
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/sig/siginfo"
)

// Cfg is a direct Go representation of the JSON file format.
type Cfg struct {
	ASes          map[addr.IA]*ASEntry
	ConfigVersion uint64
}

// Load a JSON config file from path and parse it into a Cfg struct.
func LoadFromFile(path string) (*Cfg, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, common.NewBasicError("Unable to open SIG config", err)
	}
	cfg := &Cfg{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, common.NewBasicError("Unable to parse SIG config", err)
	}
	cfg.postprocess()
	return cfg, nil
}

// postprocess sets the SIG IDs of the SIG objects in cfg according the keys in
// SIGSet.
func (cfg *Cfg) postprocess() {
	// Populate IDs
	for _, as := range cfg.ASes {
		for id := range as.Sigs {
			sig := as.Sigs[id]
			sig.Id = id
		}
	}
}

type ASEntry struct {
	Name string
	Nets []*IPNet
	Sigs SIGSet
}

// IPNet is custom type of net.IPNet, to allow custom unmarshalling.
type IPNet net.IPNet

func (in *IPNet) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return common.NewBasicError("Unable to unmarshal IPnet from JSON", err, "raw", b)
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return common.NewBasicError("Unable to parse IPnet string", err, "raw", s)
	}
	if !ip.Equal(ipnet.IP) {
		return common.NewBasicError("Network is not canonical (should not be host address).",
			nil, "raw", s)
	}
	*in = IPNet(*ipnet)
	return nil
}

func (in *IPNet) MarshalJSON() ([]byte, error) {
	return json.Marshal(in.String())
}

func (in *IPNet) IPNet() *net.IPNet {
	return (*net.IPNet)(in)
}

func (in *IPNet) String() string {
	return (*net.IPNet)(in).String()
}

// SIG represents a SIG in a remote IA.
type SIG struct {
	Id        siginfo.SigIdType `json:"-"`
	Addr      net.IP
	CtrlPort  uint16
	EncapPort uint16
}

type SIGSet map[siginfo.SigIdType]*SIG
