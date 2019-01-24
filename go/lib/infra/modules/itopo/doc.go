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

/*
Package itopo stores the static and dynamic topology. Client packages
that grab a reference with Get are guaranteed to receive a stable
snapshot of the topology. The returned value is the topology that is
currently active.

There are two types of topologies, the static and the dynamic topology.
For more information see lib/discovery.

Initialization

The package must be initialized with Init. In subsequent updates through
SetStatic or SetDynamic, the new topology is checked whether it is
compatible with the previous version. The rules differ between services.

If the dynamic topology is set, the initializing client should start
the periodic cleaner to evict expired dynamic topologies.

Updates

The update of the topology is only valid if a set of constraints is
met. The constraints differ between dynamic and static topology, and
also between the initialized service type.

In a static topology update, when the diff is empty, the static
topology is only updated if it expires later than the current static.
Otherwise, SetStatic succeeds and indicates that the in-memory copy
has not been updated.

A static topology update can force the dynamic topology to be dropped,
if it does no longer meet the constraints.

Constraints

The topology is split into five parts. An update is valid under the
constraints, if the constraints for each part are met.

Immutable:
This part may not differ from the initial static topology.

Mutable:
This part may differ from the initial static topology. It may also
differ between the currently active static and dynamic topology.

Semi-Mutable:
This part may differ between static topology versions. However, it
may not differ between the current dynamic and static topology.
If an update to the static topology modifies this part, the dynamic
topology is dropped.

Time:
This part is ignored when validating the constraints. It is used
to determine if a topology shall be updated if there are no
differences in the other parts.

Ignored:
This part is always ignored.

Default Topology Split

The topology file for default initialization (calling Init) is split
into immutable, mutable, time and ignored.

 ISD_AS                Immutable
 Core                  Immutable
 Overlay               Immutable
 MTU                   Immutable

 Service Entries       Mutable
 BorderRouter Entries  Mutable

 Timestamp             Time
 TTL                   Time

 TimestampHuman        Ignored

Service Topology Split

The topology file for services is split into immutable, mutable,
time and ignored.

 ISD_AS                Immutable
 Core                  Immutable
 Overlay               Immutable
 MTU                   Immutable
 OwnSvcType[OwnID]     Immutable // The service entry for the initialized element.

 Service Entries       Mutable   // Except OwnSvcType[OwnID].
 BorderRouter Entries  Mutable

 Timestamp             Time
 TTL                   Time

 TimestampHuman        Ignored

Border Router Topology Split

The topology file for border routers is split into immutable,
semi-mutable, mutable, time and ignored.

 ISD_AS                              Immutable
 Core                                Immutable
 Overlay                             Immutable
 MTU                                 Immutable
 BorderRouters[OwnId][InternalAddrs] Immutable    // Internal address of initialized router.
 BorderRouters[OwnId][CtrlAddr]      Immutable    // Control address of initialized router.

 BorderRouters[OwnId][Interfaces]    Semi-Mutable // Interfaces of initialized router.

 Service Entries       Mutable
 BorderRouter Entries  Mutable                    // Except BorderRouters[OwnId].

 Timestamp             Time
 TTL                   Time

 TimestampHuman        Ignored

Callbacks

The client package can register callbacks to be notified about
certain events.
*/
package itopo
