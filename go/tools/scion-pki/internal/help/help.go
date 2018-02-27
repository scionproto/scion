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

package help

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
)

// Help implements the 'help' command.
func Help(args []string) {
	if len(args) == 0 {
		PrintUsage()
		return
	}
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "usage: scion-pki help command\n\nToo many arguments given.\n")
		os.Exit(2)
	}
	for _, cmd := range base.Commands {
		if cmd.Name == args[0] {
			cmd.Help()
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Unknown help topic %#q. Run 'scion-pki help'.\n", args[0])
	os.Exit(2)
}

var usageTemplate = `scion-pki is a helper tool for managing the SCION Control-Plane PKI.

Usage:

	scion-pki command [arguments]

The commands are:
{{range .}}
	{{.Name | printf "%-11s"}} {{.Short}}{{end}}

Use "scion-pki help [command]" for more information about a command.
`

func PrintUsage() {
	base.Tmpl(usageTemplate, base.Commands)
}
