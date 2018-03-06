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
package certs

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runTemplate(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	isdDirs, asDirs, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	fmt.Println("Generating cert config templates.")
	for i, isdDir := range isdDirs {
		tconf, err := conf.LoadTrcConf(isdDir)
		if err != nil {
			base.ErrorAndExit("Error reading isd.ini: %s\n", err)
		}
		cores, ases := pkicmn.FilterASDirs(asDirs[i], tconf.CoreIAs)
		for _, dir := range cores {
			if err = genTemplate(dir, true); err != nil {
				base.ErrorAndExit("Error generating %s: %s\n",
					filepath.Join(dir, conf.AsConfFileName), err)
			}
		}
		for _, dir := range ases {
			if err = genTemplate(dir, false); err != nil {
				base.ErrorAndExit("Error generating %s: %s\n",
					filepath.Join(dir, conf.AsConfFileName), err)
			}
		}
	}
}

func genTemplate(dir string, core bool) error {
	ia, err := pkicmn.GetIAFromPath(dir)
	if err != nil {
		panic(err)
	}
	fpath := filepath.Join(dir, conf.AsConfFileName)
	a := conf.NewTemplateAsConf(ia, core)
	if err = a.SaveTo(fpath, pkicmn.Force); err != nil {
		return err
	}
	return nil
}
