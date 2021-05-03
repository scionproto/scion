// Copyright 2021 Anapaya Systems
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

package trcs

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/file"
)

func newFormatCmd(pather command.Pather) *cobra.Command {
	var flags struct {
		out    string
		format string
		force  bool
	}
	var cmd = &cobra.Command{
		Use:   "format [flags] <trc-file>",
		Short: "Reformat a TRC or TRC payload",
		Example: fmt.Sprintf(`  %[1]s format ISD1-B1-S1.trc.der
  %[1]s format --der ISD1-B1-S2.pld --out ISD1-B1-S2.pld.der`,
			pather.CommandPath(),
		),
		Long: `'format' prints the TRC or TRC payload in a different format.

The PEM type for a TRC is 'TRC', and for a TRC payload it is 'TRC PAYLOAD'.

By default, the output is PEM encoded. DER format can be requested by providing
'der' in the --format flag. When selecting DER output, ensure stdout is
redirected to a file because the raw characters might mess up the terminal.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			origFormat := flags.format
			flags.format = strings.ToLower(flags.format)
			if flags.format != "der" && flags.format != "pem" {
				return serrors.New("format not supported", "format", origFormat)
			}
			if flags.out != "" {
				if err := file.CheckDirExists(filepath.Dir(flags.out)); err != nil {
					return serrors.WrapStr("checking that output directory exists", err)
				}
			}
			cmd.SilenceUsage = true

			filename := args[0]
			raw, err := ioutil.ReadFile(filename)
			if err != nil {
				return serrors.WrapStr("reading file", err)
			}

			var output []byte
			var pemHeader string
			pld, trc, err := decodeTRCorPayload(raw)
			switch {
			case err != nil:
				return err
			case trc != nil:
				output = trc.Raw
				pemHeader = "TRC"
			default:
				output = pld.Raw
				pemHeader = "TRC PAYLOAD"
			}

			// Encode to PEM if not requested DER.
			if flags.format != "der" {
				output = pem.EncodeToMemory(&pem.Block{
					Type:  pemHeader,
					Bytes: output,
				})
				if output == nil {
					panic("PEM encoding failed")
				}
			}

			if flags.out == "" {
				_, err := os.Stdout.Write(output)
				return err
			}

			err = file.WriteFile(flags.out, output, 0644, file.WithForce(flags.force))
			if err != nil {
				return serrors.WrapStr("writing to output file", err)
			}
			fmt.Printf("Transformation successfully written to %q\n", flags.out)
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.out, "out", "",
		"The path to write the transformation TRC or TRC payload",
	)
	cmd.Flags().StringVar(&flags.format, "format", "pem",
		"The Output format (der|pem)",
	)
	cmd.Flags().BoolVar(&flags.force, "force", false,
		"Force overwriting existing output file",
	)
	return cmd
}
