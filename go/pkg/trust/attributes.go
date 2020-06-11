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

import (
	"strings"
)

const (
	// Any indicates a primary AS with any attribute.
	Any Attribute = 0
	// Authoritative indicates an authoritative AS.
	Authoritative Attribute = 1 << iota
	// Core indicates a core AS.
	Core
	// RootCA indicates a root CA AS.
	RootCA
)

var attributeString = map[Attribute]string{
	Any:           "any",
	Authoritative: "authoritative",
	Core:          "core",
	RootCA:        "root_ca",
}

// Attribute indicates the capability of a primary AS.
type Attribute int

// IsSubset indicates if these attributes are a subset of the provided attributes.
func (a Attribute) IsSubset(super Attribute) bool {
	return (a & super) == a
}

func (a Attribute) String() string {
	parts := make([]string, 0, 3)
	for _, attr := range []Attribute{Authoritative, Core, RootCA} {
		if Attribute(a)&attr != 0 {
			parts = append(parts, attributeString[attr])
		}
	}
	if len(parts) == 0 {
		return attributeString[Any]
	}
	return strings.Join(parts, "|")
}
