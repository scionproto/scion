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

// Package keys provides a generator for AS-level keys involved in the SCION
// control plane PKI.
package keys

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

const (
	seedFileExt    = ".seed"
	masterKeyFname = "master.key"
)

var CmdKeys = &base.Command{
	Name:      "keys",
	Run:       runKeys,
	UsageLine: "keys [-h] (gen|clean) [<flags>] selector",
	Short:     "Generate keys for the SCION control plane PKI.",
	Long: `
'keys' can be used to generate all the necessary keys used in the SCION control plane PKI as well
as the AS master key.

Subcommands:
	gen
		Used to generate new keys.
	clean (NOT IMPLEMENTED)
		Used to remove all keys.

Flags:
	-d
		The root directory of all certificates and keys (default '.')
	-f
		Overwrite existing keys.
Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-11
`,
}

func init() {
	CmdKeys.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdKeys.Flag.BoolVar(&pkicmn.Force, "f", false, "")
}

func runKeys(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "gen":
		runGenKey(cmd, cmd.Flag.Args())
	case "clean":
		fmt.Println("clean is not implemented yet.")
		return
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki keys -h' for help.\n")
		os.Exit(2)
	}
}
