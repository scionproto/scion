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

// Package ifstate implements the interface state in memory structure as well
// as related tasks and handlers.
//
// # Interface state
//
// The interface state is stored in the Interfaces struct it can be created by
// calling the NewInterfaces constructor. The state of a specific interface is
// stored in the Interface struct.
//
// # Revoker
//
// The revoker is a periodic task that revokes interfaces that have timed out
// and renews revocations of already revoked interfaces. Create it with the
// NewRevoker costructor.
//
// # Handler
//
// The handler handles interface state requests. It can be instantiated with
// the NewHandler constructor.
package ifstate
