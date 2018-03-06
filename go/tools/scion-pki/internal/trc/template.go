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
package trc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/conf"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

func runTemplate(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	isdDirs, _, err := pkicmn.ProcessSelector(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		cmd.Usage()
		os.Exit(2)
	}
	fmt.Println("Generating trc config templates.")
	for _, dir := range isdDirs {
		genTemplate(dir)
	}
}

func genTemplate(dir string) error {
	isd, err := strconv.ParseUint(filepath.Base(dir)[3:], 10, 12)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generating configuration template for ISD%d\n", isd)
	t := &conf.Trc{Isd: uint16(isd)}
	return t.SaveTo(filepath.Join(dir, conf.TrcConfFileName), pkicmn.Force)
}
