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

/*
Package addr contains types for SCION addressing.

A SCION address is composed of the following parts: ISD (ISolation Domain
identifier), AS (Autonomous System idenifier), and Host (the host address).

The ISD-AS parts are often considered together. Conventionally, this is
abbreviated to "IA".

The allocations and formatting of ISDs and ASes are documented here:
https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering. Note that the
':' separator for AS formatting is not used in paths/filenames for
compatibility reasons, so '_' is used instead in those contexts.
*/
package addr
