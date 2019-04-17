// Copyright 2018 ETH Zurich
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

func br_core_multi() int {
	var failures int

	failures += br_core_coreIf()

	failures += br_core_childIf()

	failures += core_to_core()
	failures += xover_core_to_child()
	failures += xover_child_to_core()
	failures += xover_child_to_child()

	failures += revocation_core_to_local_isd()

	return failures
}

func br_core_coreIf() int {
	var failures int

	failures += core_to_internal_host()
	failures += internal_host_to_core()
	// XXX Any value in implementing following two tests?
	//failures += core_to_internal_core()
	//failures += internal_core_to_core()
	failures += xover_core_to_internal_child()
	failures += xover_internal_child_to_core()

	return failures
}

func br_core_childIf() int {
	var failures int

	failures += child_to_internal_host()
	failures += internal_host_to_child()
	failures += xover_child_to_internal_core()
	failures += xover_internal_core_to_child()
	failures += xover_child_to_internal_child()
	failures += xover_internal_child_to_child()

	return failures
}
