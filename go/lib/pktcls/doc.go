// Copyright 2017 ETH Zurich
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

// Package class implements tools for classifying and acting on network
// packets.
//
// A class is a named condition that exposes an Eval method; when Eval yields
// true for a ClsPkt, that packet is considered to be part of that class.
//
// The following conditions are supported:
// AnyOf, AllOf, Boolean true, Boolean false and IPv4. AnyOf returns true if at
// least one subcondition returns true. AllOf returns true if all subconditions
// return true.  AllOf or AnyOf without subconditions return true. Boolean
// conditions always return their internal value. IPv4 conditions include
// predicates that compare the analyzed packet to preset values. Supported IPv4
// conditions currently include destination network match, source network match
// and ToS field match. Multiple predicates can be checked by enumerating them
// under AllOf or AnyOf.
//
// Actions are marshalable objects that describe a process. Currently, the only
// supported actions are Path Filters (ActionFilterPaths), which are containers
// for a pathmgr.PathPredicate object.
//
// Marshalable policies can be implemented by external code by mapping Cond
// items to Action items.
//
// Package class supports JSON marshaling and unmarshaling of classes and
// actions.  Due to the custom formatting of the JSON output, marshaling must
// be done by first adding the classes and actions to a ClassMap or ActionMap,
// respectively. Unmarshaling back to the Map is guaranteed to yield an object
// that is identical to the initial one.
package pktcls
