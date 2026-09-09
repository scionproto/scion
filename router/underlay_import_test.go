// Copyright 2025 SCION Association
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

package router_test

import (
	_ "github.com/scionproto/scion/router/underlayproviders/udpip"
)

// This file exists for the sole purpose of importing underlayproviders, so white-box tests, which
// are part of the router package have working underlay providers without having to create
// mocks. Nothing in the router package can import an underlay provider, since non-trivial underlay
// providers have to import the router.
//
// This file has to be in the router_test package as this is the only package that can get mixed
// in the same test without the router package importing it.
//
// Outside of tests, underlay providers are imported by the main or config packages.
//
// Note that tests have expectations about which underlay provider is installed: the afpacket
// underlay provider wouldn't do. Do not import both: the afpacket implementation has the same
// name and a higher precedence.
