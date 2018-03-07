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

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runGenIsdTmpl(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	asMap, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		base.ErrorAndExit("Error: %s\n", err)
	}
	fmt.Println("Generating trc config templates.")
	for isd := range asMap {
		genIsdTmpl(isd)
	}
}

func genIsdTmpl(isd int) error {
	dir := pkicmn.GetIsdPath(isd)
	fmt.Printf("Generating configuration template for ISD%d\n", isd)
	i := &conf.Isd{Trc: &conf.Trc{Version: 1}}
	return i.Write(filepath.Join(dir, conf.IsdConfFileName), pkicmn.Force)
}
