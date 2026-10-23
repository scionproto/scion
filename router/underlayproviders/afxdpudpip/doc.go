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

// This file has no build constraint, unlike the rest of the package.
// The router imports the package on all platforms, and that import needs at least one Go file.

// Package afxdpudpip implements the SCION router's udpip underlay with AF_XDP sockets.
// The router uses it only if router.preferred_underlays.udpip is "afxdp".
// It's built only for Linux on amd64 and arm64, and is empty elsewhere.
package afxdpudpip
