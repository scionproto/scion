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

	"github.com/scionproto/scion/go/pkg/command"
	"github.com/scionproto/scion/go/scion-pki/certs"
	"github.com/scionproto/scion/go/scion-pki/key"
	"github.com/scionproto/scion/go/scion-pki/testcrypto"
	"github.com/scionproto/scion/go/scion-pki/trcs"
)

func main() {
	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   executable,
		Short: "SCION Control Plane PKI Management Tool",
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
		newVersion(),
		key.Cmd(cmd),
		certs.Cmd(cmd),
		trcs.Cmd(cmd),
		testcrypto.Cmd(cmd),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
