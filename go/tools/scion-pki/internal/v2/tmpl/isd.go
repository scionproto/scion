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

func runGenISDTmpl(selector string) error {
	asMap, err := pkicmn.ProcessSelector(selector)
	if err != nil {
		return err
	}
	pkicmn.QuietPrint("Generating trc config templates.\n")
	for isd := range asMap {
		if err := genISDTmpl(isd); err != nil {
			return common.NewBasicError("error generating isd.ini template", err, "isd", isd)
		}
	}
	return nil
}

func genISDTmpl(isd addr.ISD) error {
	dir := pkicmn.GetIsdPath(pkicmn.RootDir, isd)
	pkicmn.QuietPrint("Generating configuration template for ISD%d\n", isd)
	i := conf.NewTemplateISDCfg()
	return i.Write(filepath.Join(dir, conf.ISDCfgFileName), pkicmn.Force)
}
