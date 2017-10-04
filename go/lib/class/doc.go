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
// packets. All components can be exported to JSON and imported back.
//
// A class specifies what actions to perform on which traffic. Method Process
// receives SCION host packets (HPkt), and evaluates the internal condition
// using that packet as input. If the evaluation returns true, then the actions
// (if any) are performed on the packet, in order. If the evaluation yiels
// false, the packet is unchanged. Method Eval acts similarly, except no action
// is performed regardless of evaluation result.
//
// Each class must include a condition. The following conditions are supported:
// AnyOf, AllOf, Boolean true, Boolean false and IPv4. AnyOf returns true if at
// least one subcondition returns true. AllOf returns true if all subconditions
// return true.  AllOf or AnyOf without subconditions return true. Boolean
// conditions always return their internal value. IPv4 conditions include
// predicates that compare the analyzed packet to preset values. Supported IPv4
// conditions currently include destination network match, source network match
// and ToS field match. Multiple predicates can be checked by enumerating them
// under AllOf or AnyOf.
//
// Actions dictate how the analyzed packet is changed. Currently, the only
// supported action is Path Pinning. If a packet has a set of possible paths,
// they are evaluated to see which (if any) match the path pinning predicate.
// The predicate specifies which consecutive sequence of ASes and interfaces
// the packet must travel through. Wildcard ISDs, ASes and IFIDs are specified
// with *. For example, a path pinning predicate that only pins paths which pass
// through ISD1 at some point is created like:
//     pp, err = NewActionPinPath("1-*.*")
//
// To pin paths passing through ISD-AS 1-11 interface 27 and then ISD-AS 1-12 interface 95:
//     pp, err = NewActionPinPath("1-11.27,1-12.95")
//
// The first path that matches is pinned and stored in the HPkt. Calling code
// can then use the path to forward the packet.
//
// This package only includes per packet analysis, with no state. Complex
// policies like shapers, policers and applying policies and classes to
// interfaces should be handled externally.
//
// Package class supports JSON marshaling and unmarshaling of classes, conditions and
// actions.
package class
