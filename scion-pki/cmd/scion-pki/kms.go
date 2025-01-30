// Copyright 2024 Anapaya Systems
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
	"io"
	"os/exec"
	"strings"
	"text/template"
	"unicode"

	"github.com/spf13/cobra"

	scionpki "github.com/scionproto/scion/scion-pki"
)

func newKms(_ CommandPather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "kms [command]",
		Short: "Run the step-kms-plugin",
		Long: `This command leverages the step-kms-plugin to interact with cloud Key Management
Systems (KMS) and Hardware Security Modules (HSM).

The commands are passed directly to the step-kms-plugin. For more information on
the available commands and their usage, please refer to the step-kms-plugin
documentation at https://github.com/smallstep/step-kms-plugin. In order to enable
KMS support, the step-kms-plugin must be installed and available in the PATH.

Various commands of the scion-pki tool allow the use of KMS. In all cases, the
private key needs to already exist in the KMS. To instruct the scion-pki tool to
use the key in the KMS, the --kms flag must be set.

For more information about supported KMSs and uri pattern, please consult
https://smallstep.com/docs/step-ca/cryptographic-protection.
`,
		RunE: func(c *cobra.Command, args []string) error {
			file, err := scionpki.LookKms()
			if err != nil {
				return err
			}
			cmd := exec.Command(file, args...)
			cmd.Stdin = c.InOrStdin()
			cmd.Stdout = c.OutOrStdout()
			cmd.Stderr = c.ErrOrStderr()
			return cmd.Run()
		},
	}
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		if len(args) <= 2 {
			err := tmpl(c.OutOrStdout(), `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}`, c)
			if err != nil {
				c.PrintErrln(err)
			}
			fmt.Fprintf(c.OutOrStdout(), "\n\nstep-kms-plugin help output:\n\n")
		}

		file, err := scionpki.LookKms()
		if err != nil {
			c.PrintErrln(err)
			return
		}

		cmd := exec.Command(file, args[1:]...)
		cmd.Stdin = c.InOrStdin()
		cmd.Stdout = c.OutOrStdout()
		cmd.Stderr = c.ErrOrStderr()
		if err := cmd.Run(); err != nil {
			c.PrintErrln(err)
		}
	})

	return cmd
}

// tmpl executes the given template text on data, writing the result to w.
func tmpl(w io.Writer, text string, data any) error {
	t := template.New("top")
	t.Funcs(templateFuncs)
	template.Must(t.Parse(text))
	return t.Execute(w, data)
}

var templateFuncs = template.FuncMap{
	"trim":                    strings.TrimSpace,
	"trimRightSpace":          trimRightSpace,
	"trimTrailingWhitespaces": trimRightSpace,
	"rpad":                    rpad,
	"removeEscape":            removeEscape,
}

func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// rpad adds padding to the right of a string.
func rpad(s string, padding int) string {
	return fmt.Sprintf("%-*s", padding, s)
}
