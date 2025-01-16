// Copyright 2024 SCION Association
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

// Package router implements the SCION border router (BR) component as a self-contained process.
//
// The code in this package is organized as follows:
//   - connector.go: implementation of the management API.
//   - dataplane.go: forwards packets between underlay connections.
//   - fnv1aCheap.go: a domain-specific implementation of the fnv1a hash function.
//   - metrics.go: manages the monitoring sensors.
//   - serialize_proxy.go: a domain-specific implementation of gopacket.SerializeBuffer.
//   - svc.go: maps a service address to a set of possible destinations.
//   - subpackages and tests.
package router
