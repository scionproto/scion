// Copyright 2019 Anapaya Systems
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

// A tool to download all logs from a specific build.

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/buildkite/go-buildkite/buildkite"

	"github.com/scionproto/scion/go/lib/serrors"
)

var (
	tokenFlag = flag.String("token", "", "The buildkite API token")
	destDir   = flag.String("dst", "",
		"The destination dir for the downloaded logs, must be writable (default: current dir)")
	orgFlag = flag.String("org", "scionproto",
		"The organization slug on buildkite (default: scionproto)")
	pipelineFlag = flag.String("pipeline", "scionproto",
		"The name of the pipeline (default: scionproto)")
	buildFlag = flag.Int("build", 0, "The build number")
)

func main() {
	os.Exit(realMain())
}

// buildDesc describes the relevant info to get build information from the buildkite API.
type buildDesc struct {
	org      string
	pipeline string
	id       string
}

func realMain() int {
	flag.Parse()
	if err := createDstDir(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create dest dir: %s\n", err)
	}
	bd, err := verifyFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	config, err := buildkite.NewTokenConfig(*tokenFlag, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init buildkite cfg: %s\n", err)
		return 1
	}
	client := buildkite.NewClient(config.Client())
	if err := downloadBuildArtifacts(client, bd); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to download artifacts %s\n", err)
		return 1
	}
	return 0
}

func createDstDir() error {
	return os.MkdirAll(*destDir, os.ModePerm)
}

func verifyFlags() (buildDesc, error) {
	var problems []string
	if *tokenFlag == "" {
		problems = append(problems, "API-Token not provided")
	}
	if *buildFlag == 0 {
		problems = append(problems, "Build number not provided")
	}
	if len(problems) > 0 {
		return buildDesc{}, serrors.New("Not all required flags provided",
			"problems", strings.Join(problems, "\n"))
	}
	return buildDesc{
		org:      *orgFlag,
		pipeline: *pipelineFlag,
		id:       strconv.Itoa(*buildFlag),
	}, nil
}

func downloadBuildArtifacts(c *buildkite.Client, bd buildDesc) error {
	b, _, err := c.Builds.Get(bd.org, bd.pipeline, bd.id)
	if err != nil {
		return err
	}
	artifacts, _, err := c.Artifacts.ListByBuild(bd.org, bd.pipeline, bd.id,
		&buildkite.ArtifactListOptions{
			ListOptions: buildkite.ListOptions{
				PerPage: 100,
			},
		})
	if err != nil {
		return err
	}
	for _, artifact := range artifacts {
		if artifact.DownloadURL == nil {
			fmt.Fprintf(os.Stderr, "Artifact %s has no download URL, ignored\n", *artifact.ID)
			continue
		}
		if artifact.Filename == nil || !strings.HasPrefix(*artifact.Filename, "buildkite") {
			fmt.Fprintf(os.Stderr, "Ignore artifiact %s because of filename %s\n",
				*artifact.ID, *artifact.Filename)
			continue
		}
		job := jobForArtifact(b, &artifact)
		if job == nil {
			fmt.Fprintf(os.Stderr, "No job found for artifact: %s\n", *artifact.ID)
			continue
		}
		if err := downloadJobArtifacts(c, job, &artifact); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to download artifacts for job %s: %s\n", *job.Name, err)
		}
	}
	return nil
}

func jobForArtifact(b *buildkite.Build, a *buildkite.Artifact) *buildkite.Job {
	if a.JobID == nil {
		return nil
	}
	for _, job := range b.Jobs {
		if job.ID != nil && *job.ID == *a.JobID {
			return job
		}
	}
	return nil
}

func downloadJobArtifacts(c *buildkite.Client, j *buildkite.Job, a *buildkite.Artifact) error {
	mangledJobName := strings.Replace(*j.Name, " ", "_", -1)
	f, err := os.Create(fmt.Sprintf("%s/%s_%s_%s", *destDir, mangledJobName, *j.ID, *a.Filename))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = c.Artifacts.DownloadArtifactByURL(*a.DownloadURL, f)
	return err
}
