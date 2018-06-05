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
package tmpl

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenAsTmpl(args []string) {
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		pkicmn.ErrorAndExit("Error: %s\n", err)
	}
	pkicmn.QuietPrint("Generating cert config templates.\n")
	for isd, ases := range asMap {
		iconf, err := conf.LoadIsdConf(pkicmn.GetIsdPath(pkicmn.RootDir, isd))
		if err != nil {
			pkicmn.ErrorAndExit("Error reading %s: %s\n", conf.IsdConfFileName, err)
		}
		for _, ia := range ases {
			if err = genAsTmpl(ia, iconf); err != nil {
				pkicmn.ErrorAndExit("Error generating %s template for %s: %s\n",
					conf.AsConfFileName, ia, err)
			}
		}
	}
}

func genAsTmpl(ia addr.IA, isdConf *conf.Isd) error {
	core := pkicmn.Contains(isdConf.Trc.CoreIAs, ia)
	a := conf.NewTemplateAsConf(ia, isdConf.Trc.Version, core)
	dir := pkicmn.GetAsPath(pkicmn.RootDir, ia)
	fpath := filepath.Join(dir, conf.AsConfFileName)
	if err := a.Write(fpath, pkicmn.Force); err != nil {
		return err
	}
	return nil
}
