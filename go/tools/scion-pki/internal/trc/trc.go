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

// Package trc provides a generator for Trust Root Configuration (TRC) files for the SCION
// control plane PKI.
package trc

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/go/tools/scion-pki/internal/base"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

var CmdTrc = &base.Command{
	Name:      "trc",
	Run:       runTrc,
	UsageLine: "trc [-h] gen [<flags>] selector",
	Short:     "Generate TRCs for the SCION control plane PKI",
	Long: `
'trc' can be used to generate Trust Root Configuration (TRC) files used in the SCION control
plane PKI.

The following subcommands are available:
	gen
		Used to generate new TRCs.

The following flags are available:
	-d
		The root directory of on which 'scion-pki' operates.
	-f
		Overwrite existing TRCs.

Selector:
	*
		All ISDs under the root directory.
	X
		ISD X.

'trc' needs to be pointed to the root directory where all keys and certificates are
stored on disk (-d flag). It expects the contents of the root directory to follow
a predefined structure:
	<root>/
		ISD1/
			isd.ini
			AS1/
			AS2/
			...
		ISD2/
			isd.ini
			AS1/
			...
		...

isd.ini contains the preconfigured parameters according to which 'trc' generates
the TRCs. It follows the ini format and can contain only the default section with
the following values:
	Description [optional]
		arbitrary string used to describe the ISD/TRC
and a section 'TRC' with the following values:
	Version [required]
		integer representing the version of the TRC
	Validity [required]
		the validity of the TRC as a duration string, e.g., 180d or 36h
	CoreASes [required]
		comma-separated list of ISD-AS identifiers representing the core ASes of the ISD.
	IssuingTime (now) [optional]
		the time the TRC was created as a UNIX timestamp
	GracePeriod (0) [optional]
		integer reprensenting the time the previous TRC is still valid in seconds
	QuorumTRC [required]
		integer reprensenting the number of core ASes needed to sign a new TRC.
`,
}

func init() {
	CmdTrc.Flag.StringVar(&pkicmn.RootDir, "d", ".", "")
	CmdTrc.Flag.BoolVar(&pkicmn.Force, "f", false, "")
}

func runTrc(cmd *base.Command, args []string) {
	if len(args) < 1 {
		cmd.Usage()
		os.Exit(2)
	}
	subCmd := args[0]
	cmd.Flag.Parse(args[1:])
	switch subCmd {
	case "gen":
		runGenTrc(cmd, cmd.Flag.Args())
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand '%s'\n", args[0])
		fmt.Fprintf(os.Stderr, "run 'scion-pki trc -h' for help.\n")
		os.Exit(2)
	}
	os.Exit(0)
}
