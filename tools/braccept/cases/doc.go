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

/*
Package cases contains router acceptance cases that can be integrated
into the braccept binary.

The process to add a new case is the following:

Step 0. Refer to the following for the test's setup:
  - Overview: acceptance/router_multi/topology.drawio.png
  - Topology Details: acceptance/router_multi/conf/topology.json
  - MAC Addresses: acceptance/router_multi/test.py
    Note that all MAC addresses of interfaces on the far side
    of the A/B/C/D routers are identical: f00d:cafe:beef

Step 1. Add a new file with a representative name
e.g. cases/child_to_child_xover.go

Step 2. Create a function inside that file which returns the new br accept
testcase.

	// ChildToChildXover  <ADD DESCRIPTION>
	func ChildToChildXover(artifactsDir string, mac hash.Hash) runner.Case {

	...

		return runner.Case{
			Dscr:     "ChildToChild",
			WriteTo:  "veth_151_host",
			ReadFrom: "veth_141_host",
			Input:    input.Bytes(),
			Want:     want.Bytes(),
		}
	}

Step 3. In the braccept/main.go, include the above function

	multi := []runner.Case{
		cases.ChildToParent(artifactsDir, mac),
		cases.ChildToChildXover(artifactsDir, mac),
	}

Step 4. Do a local run, which means set up a working router, execute the
braccept, shutdown the router. This is done in sequence by:

	bazel test acceptance/router_multi:all --config=integration --nocache_test_results
*/
package cases
