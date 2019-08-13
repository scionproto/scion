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
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "tmpl",
	Short: "Generate configuration templates for ISDs and ASes.",
	Long: `
'tmpl' can be used to generate configuration file templates for ISDs and ASes.
`,
}

var isd = &cobra.Command{
	Use:   "isd",
	Short: "Generate an isd.ini template.",
	Long: `Arguments for isd
Selector:
	*
		All ISDs under the root directory.
	X
		A specific ISD X.
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGenIsdTmpl(args)
	},
}

var as = &cobra.Command{
	Use:   "as",
	Short: "Generate an as.ini template.",
	Long: `Arguments for as
Selector:
	*-*
		All ISDs and ASes under the root directory.
	X-*
		All ASes in ISD X.
	X-Y
		A specific AS X-Y, e.g. AS 1-ff00:0:300
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runGenAsTmpl(args)
	},
}

func init() {
	Cmd.AddCommand(isd)
	Cmd.AddCommand(as)
}
