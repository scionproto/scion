// Copyright 2026 SCION Association
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

// Package afxdp provides zero-copy-capable AF_XDP sockets.
// Interface owns the XDP program and eBPF objects; Socket binds to one RX/TX queue.
//
// AF_XDP uses four rings:
//
//   - RX: raw packets delivered from the NIC to userspace.
//   - FQ: UMEM addresses supplied by userspace for RX.
//   - TX: descriptors sent from userspace to the NIC.
//   - CQ: completed TX buffers returned by the kernel.
package afxdp
