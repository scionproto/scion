// Copyright 2025 SCION Association
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

package buildkite

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildkite/go-buildkite/v4"
	"golang.org/x/sync/errgroup"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// NewClient constructs a new buildkite client by taking the API token
// from the environment.
func NewClient() (*buildkite.Client, error) {
	token := os.Getenv("BUILDKITE_TOKEN")
	if token == "" {
		fmt.Fprint(os.Stderr, `API token is not set.
Please create a token at https://buildkite.com/user/api-access-tokens and pass it
via the BUILDKITE_TOKEN environment variable.

The following permissions are required:
- read_artifacts
- read_builds
`)
		return nil, fmt.Errorf("BUILDKITE_TOKEN not set")
	}
	return buildkite.NewClient(buildkite.WithTokenAuth(token))
}

type Downloader struct {
	Client *buildkite.Client
	Dir    string
	All    bool
	StdOut io.Writer
	StdErr io.Writer
}

func (d *Downloader) ArtifactsFromBuild(build *buildkite.Build) error {
	jobGroup, ctx := errgroup.WithContext(context.Background())
	for _, job := range build.Jobs {
		if job.ArtifactsURL == "" {
			d.info("Ignoring job without artifacts: %s\n", job.ID)
			continue
		}
		if job.StepKey == "" {
			var a string
			if job.Command != "" {
				a = " (" + job.Command + ")"
			}
			d.info("Ignoring job without step key: %s%s", job.ID, a)
			continue
		}
		if !d.All && job.ExitStatus != nil && *job.ExitStatus == 0 {
			d.info("Ignoring job that succeeded: %s", job.Name)
			continue
		}

		jobGroup.Go(func() error {
			artifacts, err := d.artifactsByURL(job.ArtifactsURL)
			if err != nil {
				return serrors.Wrap("fetching artifacts", err, "job", job.Name)
			}

			artifactsGroup, _ := errgroup.WithContext(ctx)
			for _, a := range artifacts {
				if a.DownloadURL == "" {
					d.info("Ignoring artifact %s without download URL\n", a.ID)
					continue
				}
				if a.Filename == "" || !strings.HasPrefix(a.Filename, "buildkite") {
					d.info("Ignore artifact %s because of filename: %s\n", a.ID, a.Filename)
					continue
				}

				artifactsGroup.Go(func() error {
					base := fmt.Sprintf("%s.%s", job.StepKey, job.ID)
					base = strings.ReplaceAll(base, ":", "_")

					start := time.Now()
					file := filepath.Join(d.Dir, base+".tar.gz")
					d.info("Start downloading: %s\n", file)
					if err := d.downloadArtifact(a, file); err != nil {
						return serrors.Wrap("downloading artifact", err, "job", job.Name)
					}
					d.info("Done downloading: %s (%s)\n", file, time.Since(start))

					start = time.Now()
					dir := filepath.Join(d.Dir, base)
					d.info("Start unpacking: %s\n", dir)
					if err := os.MkdirAll(dir, 0o755); err != nil {
						return err
					}
					cmd := exec.Command("tar", "-xf", file, "-C", dir, "--strip-components", "1")
					if out, err := cmd.CombinedOutput(); err != nil {
						d.error("%s", string(out))
						return err
					}
					d.info("Done unpacking: %s (%s)\n", dir, time.Since(start))
					return nil
				})
			}
			return artifactsGroup.Wait()
		})
	}
	return jobGroup.Wait()
}

func (d *Downloader) artifactsByURL(url string) ([]buildkite.Artifact, error) {
	req, err := d.Client.NewRequest(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	var artifacts []buildkite.Artifact
	if _, err := d.Client.Do(req, &artifacts); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func (d *Downloader) downloadArtifact(artifact buildkite.Artifact, file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = d.Client.Artifacts.DownloadArtifactByURL(context.Background(), artifact.DownloadURL, f)
	return err
}

func (d *Downloader) info(format string, ctx ...any) {
	if d.StdOut != nil {
		fmt.Fprintf(d.StdOut, format, ctx...)
	}
}

func (d *Downloader) error(format string, ctx ...any) {
	if d.StdErr != nil {
		fmt.Fprintf(d.StdErr, format, ctx...)
	}
}
