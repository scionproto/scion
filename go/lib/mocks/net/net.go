// Copyright 2020 Anapaya Systems
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

// Package net defines net types from the stdlib for mocking. No code should
// rely on this directly.
package net

import "net"

// Addr defines net.Addr for mocking. Do not use this, except for mocking.
type Addr = net.Addr

// Conn defines net.Conn for mocking. Do not use this, except for mocking.
type Conn = net.Conn

// PacketConn defines net.PacketConn for mocking. Do not use this, except for
// mocking.
type PacketConn = net.PacketConn
