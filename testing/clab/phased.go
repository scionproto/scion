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

package clab

import (
	"flag"
	"testing"
)

// PhasedTest selects the phases of a system test: setup (deploy the lab),
// execute (run the test against the lab) and teardown (destroy the lab). It is
// created with RegisterPhasedTest.
//
// If no phase is selected, all phases run. Selecting a subset lets a developer
// iterate: e.g. -setup once, then -execute repeatedly, then -teardown. The
// clab_system_test macro creates a target per phase.
type PhasedTest struct {
	setup    *bool
	execute  *bool
	teardown *bool
}

// RegisterPhasedTest registers the -setup, -execute and -teardown flags. Call
// it once per test binary, at package level.
func RegisterPhasedTest() PhasedTest {
	// -run is taken by the Go testing framework, hence -execute.
	return PhasedTest{
		setup:    flag.Bool("setup", false, "run the setup phase (deploy the lab)"),
		execute:  flag.Bool("execute", false, "run the execute phase (test the deployed lab)"),
		teardown: flag.Bool("teardown", false, "run the teardown phase (destroy the lab)"),
	}
}

// Setup reports whether the setup phase runs.
func (p PhasedTest) Setup() bool {
	return *p.setup || p.Default()
}

// Execute reports whether the execute phase runs.
func (p PhasedTest) Execute() bool {
	return *p.execute || p.Default()
}

// Teardown reports whether the teardown phase runs.
func (p PhasedTest) Teardown() bool {
	return *p.teardown || p.Default()
}

// Default reports whether no phase is selected explicitly, i.e., whether all
// phases run.
func (p PhasedTest) Default() bool {
	return !*p.setup && !*p.execute && !*p.teardown
}

// TeardownCleanup registers f as a cleanup of t if the teardown phase runs.
// Cleanups run in reverse order of registration, so registering the teardown
// first makes it run last, even if the test fails.
func (p PhasedTest) TeardownCleanup(t *testing.T, f func()) {
	if p.Teardown() {
		t.Cleanup(f)
	}
}
