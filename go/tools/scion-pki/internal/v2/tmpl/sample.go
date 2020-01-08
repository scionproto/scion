// Copyright 2020 ETH Zurich
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

package tmpl

const sampleTopo = `--- # Sample topology
ASes:
  "1-ff00:0:a":
    core: true
    voting: true
    authoritative: true
    cert_issuer: 1-ff00:0:c
  "1-ff00:0:b":
    voting: true
    cert_issuer: 1-ff00:0:c
  "1-ff00:0:c":
    voting: true
    issuing: true
  "1-ff00:0:d":
    cert_issuer: 1-ff00:0:c

  "2-ff00:0:e":
    core: true
    voting: true
    authoritative: true
    issuing: true
  "2-ff00:0:f":
    core: true
    voting: true
    authoritative: true
    issuing: true
`
