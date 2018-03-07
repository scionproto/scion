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

// Package tmpl provides facilities to generate ISD and AS configuration templates.
package tmpl

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var CmdTmpl = &base.Command{
	Name:      "tmpl",
	Run:       runTmpl,
	UsageLine: "tmpl [-h] (isd|as) [<flags>] selector",
	Short:     "Generate configuration templates for ISDs and ASes.",
	Long: `
'tmpl' can be used to generate configuration file templates for ISDs and ASes.

Subcommands:
	isd
		Used to generate an isd.ini template.
	as
		Used to generate an as.ini template.

Flags:
	-d
		The root directory of all certificates and keys (default '.')
	-f
		Overwrite existing keys.

Selector:
	*
		All ISDs under the root directory.
	X
		A specific ISD X.
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-11

`,
}

func init() {
	CmdTmpl.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdTmpl.Flag.BoolVar(&pkicmn.Force, "f", false, "")
}

func runTmpl(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "isd":
		runGenIsdTmpl(cmd, cmd.Flag.Args())
	case "as":
		runGenAsTmpl(cmd, cmd.Flag.Args())
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki tmpl -h' for help.\n")
		os.Exit(2)
	}
	os.Exit(0)
}
