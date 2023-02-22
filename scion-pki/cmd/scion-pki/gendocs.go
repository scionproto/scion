// Copyright 2022 Anapaya Systems
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

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/scionproto/scion/pkg/private/serrors"
)

func newGendocs(pather CommandPather) *cobra.Command {
	var cmd = &cobra.Command{
		Use:     "gendocs <directory>",
		Short:   "Generate documentation for scion-pki CLI tool",
		Example: fmt.Sprintf("  %[1]s gendocs doc/command/scion-pki", pather.CommandPath()),
		Long: `'gendocs' generate documentation for the scion-pki CLI tool.

This command creates and stores the RST documentation for the scion-pki CLI tool
in the location given as an argument.`,
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			directory := args[0]

			filePrepender := func(filename string) string {
				return ":orphan:\n\n"
			}

			linkHandler := func(name, ref string) string {
				return fmt.Sprintf(":ref:`%s <%s>`", name, ref)
			}
			if err := os.MkdirAll(directory, 0755); err != nil {
				return serrors.WrapStr("creating directory", err, "directory", directory)
			}
			err := doc.GenReSTTreeCustom(cmd.Parent(), directory, filePrepender, linkHandler)
			if err != nil {
				return serrors.WrapStr("generating RST documentation", err)
			}

			return nil
		},
	}
	return cmd
}
