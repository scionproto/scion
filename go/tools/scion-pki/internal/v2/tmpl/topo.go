// Copyright 2019 Anapaya Systems
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

package tmpl

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

var (
	notBefore   uint32
	rawValidity string
)

func runGenTopoTmpl(args []string) error {
	raw, err := ioutil.ReadFile(args[0])
	if err != nil {
		return common.NewBasicError("unable to read file", err, "file", args[0])
	}
	val, err := validityFromFlags()
	if err != nil {
		return err
	}
	var topo topoFile
	if err := yaml.Unmarshal(raw, &topo); err != nil {
		return common.NewBasicError("unable to parse topo", err, "file", args[0])
	}
	isdCfgs := make(map[addr.ISD]*conf.ISDCfg)
	for _, isd := range topo.ISDs() {
		isdCfg := genISDCfg(isd, topo, val)
		isdCfgs[isd] = isdCfg
		dir := pkicmn.GetIsdPath(pkicmn.RootDir, isd)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return common.NewBasicError("unable to make ISD directory", err, "isd", isd)
		}
		if err := isdCfg.Write(filepath.Join(dir, conf.ISDCfgFileName), pkicmn.Force); err != nil {
			return common.NewBasicError("unable to write ISD config", err, "isd", isd)
		}
	}
	for ia, entry := range topo.ASes {
		asCfg := genASCfg(ia, entry, val, isdCfgs[ia.I])
		dir := pkicmn.GetAsPath(pkicmn.RootDir, ia)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return common.NewBasicError("unable to make AS directory", err, "ia", ia)
		}
		if err := asCfg.Write(filepath.Join(dir, conf.ASConfFileName), pkicmn.Force); err != nil {
			return common.NewBasicError("unable to write AS config", err, "ia", ia)
		}
	}

	return nil
}

func genISDCfg(isd addr.ISD, topo topoFile, val validity) *conf.ISDCfg {
	cores := topo.Cores(isd)
	isdCfg := conf.NewTemplateISDCfg()
	isdCfg.Desc = fmt.Sprintf("ISD %d", isd)
	// XXX(roosd): Choose quorum according to your security needs. This simply
	// serves an example.
	isdCfg.VotingQuorum = len(cores)/2 + 1
	isdCfg.NotBefore = val.NotBefore
	isdCfg.Validity = val.Validity
	isdCfg.AuthoritativeASes = cores
	isdCfg.CoreASes = cores
	isdCfg.IssuingASes = cores
	isdCfg.VotingASes = cores
	return isdCfg
}

func genASCfg(ia addr.IA, entry asEntry, val validity, isdCfg *conf.ISDCfg) *conf.ASCfg {
	asCfg := genASTmpl(ia, isdCfg)
	asCfg.AS.NotBefore = val.NotBefore
	asCfg.AS.Validity = val.Validity
	if !entry.Issuer.IsZero() {
		asCfg.IssuerIA = entry.Issuer
	}
	if asCfg.Issuer != nil {
		asCfg.Issuer.NotBefore = val.NotBefore
		asCfg.Issuer.Validity = val.Validity
	}
	return asCfg

}

// validity is a container for the provided flags.
type validity struct {
	NotBefore uint32
	Validity  time.Duration
}

func validityFromFlags() (validity, error) {
	p, err := util.ParseDuration(rawValidity)
	if err != nil {
		return validity{}, common.NewBasicError("invalid validity", err, "input", rawValidity)
	}
	return validity{NotBefore: notBefore, Validity: p}, nil
}

// topoFile is used to parse the topology description.
type topoFile struct {
	ASes map[addr.IA]asEntry `yaml:"ASes"`
}

func (t topoFile) ISDs() []addr.ISD {
	m := make(map[addr.ISD]struct{})
	for ia := range t.ASes {
		m[ia.I] = struct{}{}
	}
	var isds []addr.ISD
	for isd := range m {
		isds = append(isds, isd)
	}
	return isds
}

func (t topoFile) Cores(isd addr.ISD) []addr.AS {
	var cores []addr.AS
	for ia, entry := range t.ASes {
		if ia.I == isd && entry.Core {
			cores = append(cores, ia.A)
		}
	}
	return cores
}

type asEntry struct {
	Core   bool    `yaml:"core"`
	Issuer addr.IA `yaml:"cert_issuer"`
}
