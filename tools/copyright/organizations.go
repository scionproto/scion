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

package main

import "strings"

// organizations are the holders of the copyright lines this tool maintains.
// -affiliation must be one of them, which keeps a misspelled holder out of the
// headers: the next run would take it for a third-party notice.
//
// A name must not contain a comma, because [splitHolders] splits a shared line on commas.
var organizations = []string{
	"SCION Association",
	"Anapaya Systems",
	"ETH Zurich",
	"OVGU Magdeburg",
}

// knownOrg returns the spelling [organizations] uses for name,
// ignoring case and surrounding space.
func knownOrg(name string) (string, bool) {
	name = strings.TrimSpace(name)
	for _, org := range organizations {
		if strings.EqualFold(org, name) {
			return org, true
		}
	}
	return "", false
}
