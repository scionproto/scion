// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func runGenASTmpl(selector string) error {
	asMap, err := pkicmn.ProcessSelector(selector)
	if err != nil {
		return err
	}
	pkicmn.QuietPrint("Generating AS config templates.\n")
	for isd, ases := range asMap {
		isdCfg, err := conf.LoadISDCfg(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			return common.NewBasicError("unable to read isd.ini", err, "isd", isd)
		}
		for _, ia := range ases {
			if err = genAndWriteASTmpl(ia, isdCfg); err != nil {
				return common.NewBasicError("error generating as.ini template", err, "ia", ia)
			}
		}
	}
	return nil
}

func genAndWriteASTmpl(ia addr.IA, isd *conf.ISDCfg) error {
	asCfg := genASTmpl(ia, isd)
	dir := pkicmn.GetAsPath(pkicmn.RootDir, ia)
	fpath := filepath.Join(dir, conf.ASConfFileName)
	if err := asCfg.Write(fpath, pkicmn.Force); err != nil {
		return err
	}
	return nil
}

func genASTmpl(ia addr.IA, isd *conf.ISDCfg) *conf.ASCfg {
	voting := pkicmn.ContainsAS(isd.TRC.VotingASes, ia.A)
	issuing := pkicmn.ContainsAS(isd.TRC.IssuingASes, ia.A)
	return conf.NewTemplateASCfg(ia, isd.TRC.Version, voting, issuing)
}
