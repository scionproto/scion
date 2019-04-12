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

// Package healthpool provides a generic way to keep track of the health
// infos for a set of keys.
//
// Usage
//
// This package is used to implement health pools for specific purposes.
// They can be found in the subpackages. Client packages should use these
// implementations, unless they implement their own specific health pool.
//
// Pool
//
// The pool keeps a map of all registered keys to their health info. It is
// used to choose the best info based on the fail count and the initialized
// selection algorithm. The behavior of the pool can be modified at
// initialization with the provided PoolOptions.
//
// The pool periodically reduces the fail count for every info that has not
// failed for a specified amount of time. The fail count is divided by two
// every expire interval starting from that point.
//
// Info
//
// The info keeps track of the failures for a given key. The client should
// call the Fail method to increase the fail count.
package healthpool
