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

package trust

// Engine keeps the SCION control-plane going.
//
// The engines is in charge of verifying control-plane messages based on the
// control-plane PKI. To that end, the engine keeps track of crypto material,
// such as CP certificates and TRCs, and resolves them where appropriate.
//
// The engine is composed of multiple parts, each with its own set of
// responsibilities.
type Engine struct {
	// Inspector determines the attributes of an AS inside its ISD.
	Inspector
	// Provider provides verified crypto material.
	Provider
	DB DB
}
