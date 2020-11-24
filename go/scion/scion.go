// Copyright 2020 Anapaya Systems
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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/pkg/app"
	"github.com/scionproto/scion/go/pkg/command"
)

var filterHelp = `The paths can be filtered according to a sequence. A sequence is a string of
space separated HopPredicates. A Hop Predicate (HP) is of the form
'ISD-AS#IF,IF'. The first IF means the inbound interface (the interface where
packet enters the AS) and the second IF means the outbound interface (the
interface where packet leaves the AS).  0 can be used as a wildcard for ISD, AS
and both IF elements independently.

HopPredicate Examples:

  Match ISD 1: 1
  Match AS 1-ff00:0:133: 1-ff00:0:133 or 1-ff00:0:133#0
  Match inbound IF 2 of AS 1-ff00:0:133: 1-ff00:0:133#2,0
  Match outbound IF 2 of AS 1-ff00:0:133: 1-ff00:0:133#0,2
  Match inbound or outbound IF 2 of AS 1-ff00:0:133: 1-ff00:0:133#2

Sequence Examples:

  sequence: "1-ff00:0:133#0 1-ff00:0:120#2,1 0 0 1-ff00:0:110#0"

The above example specifies a path from any interface in AS 1-ff00:0:133 to
two subsequent interfaces in AS 1-ff00:0:120 (entering on interface 2 and
exiting on interface 1), then there are two wildcards that each match any AS.
The path must end with any interface in AS 1-ff00:0:110.

  sequence: "1-ff00:0:133#1 1+ 2-ff00:0:1? 2-ff00:0:233#1"

The above example includes operators and specifies a path from interface
1-ff00:0:133#1 through multiple ASes in ISD 1, that may (but does not need
to) traverse AS 2-ff00:0:1 and then reaches its destination on
2-ff00:0:233#1.

Available operators:

  ? (the preceding HP may appear at most once)
  + (the preceding ISD-level HP must appear at least once)
  * (the preceding ISD-level HP may appear zero or more times)
  | (logical OR)

`

// CommandPather returns the path to a command.
type CommandPather interface {
	CommandPath() string
}

func main() {
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   executable,
		Short: "A clean-slate Internet architecture",
		Args:  cobra.NoArgs,
		// Silence the errors, since we print them in main. Otherwise, cobra
		// will print any non-nil errors returned by a RunE function.
		// See https://github.com/spf13/cobra/issues/340.
		// Commands should turn off the usage help message, if they deem the arguments
		// to be reasonable well-formed. This avoids outputing help message on errors
		// that are not caused by malformed input.
		// See https://github.com/spf13/cobra/issues/340#issuecomment-374617413.
		SilenceErrors: true,
	}
	cmd.AddCommand(
		command.NewCompletion(cmd),
		command.NewVersion(cmd),
		newPing(cmd),
		newShowpaths(cmd),
		newTraceroute(cmd),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		if code := app.ExitCode(err); code != -1 {
			os.Exit(code)
		}
		os.Exit(2)
	}
}
