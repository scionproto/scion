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

// A tool to download all artifacts from a specific build.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	bk "github.com/buildkite/go-buildkite/v2/buildkite"
	"github.com/spf13/cobra"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/app"
	"github.com/scionproto/scion/tools/buildkite"
)

func main() {
	var flags struct {
		dir      string
		org      string
		pipeline string
		all      bool
		verbose  bool
	}

	executable := filepath.Base(os.Args[0])
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s <build>", executable),
		Short: "Buildkite artifacts downloader",
		Long: `A small tool to streamline artifacts downloading from buildkite.

To interact with buildkite, the BUILDKITE_TOKEN environment variable has to be
set. The token must have the following permissions:

- read_artifacts
- read_builds
`,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			build := args[0]
			cmd.SilenceUsage = true
			client, err := buildkite.NewClient()
			if err != nil {
				return err
			}

			b, _, err := client.Builds.Get(flags.org, flags.pipeline, build, &bk.BuildsListOptions{
				IncludeRetriedJobs: true,
			})
			if err != nil {
				return serrors.Wrap("fetching build", err)
			}
			d := buildkite.Downloader{
				Client: client,
				StdErr: os.Stderr,
				All:    flags.all,
				Dir:    filepath.Join(flags.dir, build),
			}
			if flags.verbose {
				d.StdOut = os.Stdout
			}
			if err := os.MkdirAll(d.Dir, 0755); err != nil {
				return err
			}
			if err := d.ArtifactsFromBuild(b); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flags.dir, "dir", "/tmp/buildkite-artifacts",
		"Directory where the artifacts are stored",
	)
	cmd.Flags().StringVar(&flags.org, "organization", "scionproto",
		"Buildkite organization slug",
	)
	cmd.Flags().StringVar(&flags.pipeline, "pipeline", "scion",
		"Buildkite pipeline slug",
	)
	cmd.Flags().BoolVar(&flags.all, "all", false,
		"Download all artifacts, even from successful jobs",
	)
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false,
		"Verbose info output",
	)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		if code := app.ExitCode(err); code != -1 {
			os.Exit(code)
		}
		os.Exit(1)
	}
}
