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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/certs"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/help"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/keys"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/tmpl"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/trc"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/version"
)

func init() {
	flag.Usage = help.PrintUsage
	base.Commands = []*base.Command{
		certs.CmdCerts,
		keys.CmdKeys,
		tmpl.CmdTmpl,
		trc.CmdTrc,
		version.CmdVersion,
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	// Verify that a subcommand has been provided
	if len(args) < 1 {
		help.PrintUsage()
		os.Exit(2)
	}
	// Special case 'help' command.
	if args[0] == "help" {
		help.Help(args[1:])
		return
	}
	// Run provided subcommand.
	for _, cmd := range base.Commands {
		if cmd.Name == args[0] {
			cmd.Flag.Usage = func() { cmd.Help() }
			if err := cmd.Flag.Parse(args[1:]); err != nil {
				if err == flag.ErrHelp {
					os.Exit(0)
				}
				fmt.Fprintf(os.Stderr, "An error occurred: %s\n", err.Error())
				os.Exit(2)
			}
			cmd.Run(cmd, cmd.Flag.Args())
			// If the subcommand does not call os.Exit(code) exit with code 0
			os.Exit(0)
		}
	}
	fmt.Fprintf(os.Stderr, "Unknown command: '%s'\n", args[0])
	help.PrintUsage()
	os.Exit(2)
}
