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
// # Handler
//
// Call NewHandler to create a beacon handler that implements infra.Handler. The
// handler validates the received beacon and verifies all signatures. If
// successful, the beacon is added to the beacon store.
//
// # Originator
//
// The originator should only be instantiated by core beacon servers. It
// periodically creates fresh beacons and propagates them on all core and child
// links. In case the task is run before a full period has passed, beacons are
// originated on all interfaces that have last been originated on more than one
// period ago.
//
// # Registrar
//
// The registrar is a periodic task to register segments with the appropriate
// path server. Core and Up segments are registered with the local path server.
// Down segments are registered with the originating core AS. In case the task
// is run before a full period has passed, segments are only registered, if
// there has not been a successful registration in the last period.
//
// # Propagator
//
// The propagator is a periodic task to propagate beacons to the appropriate
// neighboring ASes. In a core AS, the beacons are propagated to the neighbors
// on all core link, unless they will create an AS loop. In a non-core AS, the
// beacons are propagated to the neighbors on all child links. In case the task
// is run before a full period has passed, beacons are propagated on all
// interfaces that have last been propagated on more than one period ago.
package beaconing
