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

package trust

import "net"

// FIXME(scrye): When reloading support gets added again, Options should include
// all the reloadable aspects of the trust store. Instead of direct access,
// accessors should be preferred to ensure concurrency-safe reads.

type Config struct {
	// MustHaveLocalChain states that chain requests for the trust store's own
	// IA must always return a valid chain. This is set to true on CSes and to
	// false on others.
	MustHaveLocalChain bool
	// LocalCSes must have a length of 0 on CS nodes. On others, a random entry
	// is queried for TRCs and Chains.
	LocalCSes []net.Addr
}
