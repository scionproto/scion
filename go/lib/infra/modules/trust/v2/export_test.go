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

package trust

var (
	// NewCryptoProvider allows instantiating the private cryptoProvider for
	// black-box testing.
	NewCryptoProvider = newTestCryptoProvider
	// newTestInspector allows instantiating the private inspector for
	// black-box testing.
	NewTestInspector = newTestInspector
	// NewResolver allows instantiating the private resolver for black-box
	// testing.
	NewResolver = newTestResolver
)

// newTestCryptoProvider returns a new crypto provider for testing.
func newTestCryptoProvider(db DBRead, recurser Recurser, resolver Resolver, router Router,
	alwaysCacheOnly bool) CryptoProvider {

	return &cryptoProvider{
		db:              db,
		recurser:        recurser,
		resolver:        resolver,
		router:          router,
		alwaysCacheOnly: alwaysCacheOnly,
	}
}

// newTestInspector returns a new inspector for testing.
func newTestInspector(provider CryptoProvider) Inspector {
	return &inspector{
		provider: provider,
	}
}

// newTestResolver returns a new resolver for testing.
func newTestResolver(db DBRead, inserter Inserter, rpc RPC) Resolver {
	return &resolver{
		db:       db,
		inserter: inserter,
		rpc:      rpc,
	}
}
