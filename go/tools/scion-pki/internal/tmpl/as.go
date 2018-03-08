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
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenAsTmpl(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		base.ErrorAndExit("Error: %s\n", err)
	}
	fmt.Println("Generating cert config templates.")
	for isd, ases := range asMap {
		iconf, err := conf.LoadIsdConf(pkicmn.GetIsdPath(isd))
		if err != nil {
			base.ErrorAndExit("Error reading %s: %s\n", conf.IsdConfFileName, err)
		}
		for _, ia := range ases {
			if err = genAsTmpl(ia, iconf); err != nil {
				base.ErrorAndExit("Error generating %s template for %s: %s\n",
					conf.AsConfFileName, ia, err)
			}
		}
	}
}

func genAsTmpl(ia addr.IA, isdConf *conf.Isd) error {
	core := pkicmn.Contains(isdConf.Trc.CoreIAs, ia)
	a := conf.NewTemplateAsConf(ia, isdConf.Trc.Version, core)
	dir := pkicmn.GetAsPath(ia)
	fpath := filepath.Join(dir, conf.AsConfFileName)
	if err := a.Write(fpath, pkicmn.Force); err != nil {
		return err
	}
	return nil
}
