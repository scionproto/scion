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
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "trc",
	Short: "Generate TRCs for the SCION control plane PKI",
	Long: `
'trc' can be used to generate Trust Root Configuration (TRC) files used in the SCION control
plane PKI.

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

var gen = &cobra.Command{
	Use:   "gen",
	Short: "Generate new TRCs",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGenTrc(args)
	},
}

func init() {
	Cmd.AddCommand(gen)
}
