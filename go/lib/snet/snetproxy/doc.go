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

// Package snetproxy implements transparent logic for reconnecting to the
// dispatcher.
//
// This is done via two types: ProxyConn, a wrapper around snet.Conn that
// supports transparent reconnects, and ProxyNetwork, a wrapper around
// snet.Network that provides some helper functions for initializing ProxyConns
// (e.g., creating callbacks and checking that addresses stay the same).
// Callers can opt to use the helper ProxyNetwork, or manage reconnection logic
// themselves by using ProxyConn directly.
package snetproxy
