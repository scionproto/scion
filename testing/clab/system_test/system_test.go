// Copyright 2026 Anapaya Systems
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

// Package system_test drives a containerlab SCION topology end to end: it
// deploys the topology, runs the e2e_scion and e2e_http tests against it, and
// destroys it. See the clab package for the phases.
package system_test

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/testing/clab"
)

var (
	phased = clab.RegisterPhasedTest()

	labName  = flag.String("lab", "scion", "containerlab lab name")
	topoFile = flag.String("topo", clab.EnvOr("CLAB_TOPO", "topology/default-no-peers.topo"),
		"testgen topology description file",
	)
)

// env names of the test drivers. The go_test target wires these to
// $(rootpath ...) paths.
const (
	envE2EScion = "E2E_SCION_BIN"
	envE2EHTTP  = "E2E_HTTP_BIN"
)

// TestSystem runs the selected phases against a containerlab SCION topology.
func TestSystem(t *testing.T) {
	env := clab.NewEnvironment(t, phased, *labName)
	// Register the teardown first, so that it runs last, even if the test
	// fails. When only -teardown is requested, this cleans up a lab left
	// behind by a previous -setup run.
	phased.TeardownCleanup(t, func() { env.Destroy(t) })

	if phased.Setup() {
		env.Deploy(t, *topoFile)
	}
	if !phased.Execute() {
		return
	}

	// The output of each driver is captured as an artifact, also (and
	// especially) when the driver fails.
	t.Run("e2e_scion", func(t *testing.T) {
		out, err := env.Exec(t, clab.RunfileEnv(t, envE2EScion),
			"--gen", env.GenDir,
			"--lab", env.LabName,
			"--docker", env.DockerCmd(),
		)
		env.Collect(t, out, "e2e_scion.log")
		require.NoError(t, err, "e2e_scion failed")
	})
	t.Run("e2e_http", func(t *testing.T) {
		out, err := env.Exec(t, clab.RunfileEnv(t, envE2EHTTP), "run",
			"--gen", env.GenDir,
			"--lab", env.LabName,
			"--docker", env.DockerCmd(),
		)
		env.Collect(t, out, "e2e_http.log")
		require.NoError(t, err, "e2e_http failed")
	})
}
