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

// Package beaconing implements tasks and handlers related to beacon propagation
// and registration.
//
// Handler
//
// Call NewHandler to create a beacon handler that implements infra.Handler. The
// handler validates the received beacon and verifies all signatures. If
// successful, the beacon is added to the beacon store.
//
// Originator
//
// The originator should only be instantiated by core beacon servers. It
// periodically creates fresh beacons and propagates them on all core and child
// links.
//
// Registrar
//
// The registrar is a periodic task to register segments with the appropriate
// path server. Core and Up segments are registered with the local path server.
// Down segments are registered with the originating core AS.
package beaconing
