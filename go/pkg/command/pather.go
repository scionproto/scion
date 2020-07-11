// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package command

import "strings"

// Pather returns the path to a command.
type Pather interface {
	CommandPath() string
}

// StringPather implements Pather for the string type.
type StringPather string

func (s StringPather) CommandPath() string {
	return string(s)
}

// JoinedPather joins together the paths of multiple Pather objects.
type JoinedPather []Pather

// CommandPath concatenates all the pather in the list.
func (l JoinedPather) CommandPath() string {
	var parts []string
	for _, p := range l {
		parts = append(parts, p.CommandPath())
	}
	return strings.Join(parts, " ")
}

// Join links two pathers.
func Join(a, b Pather) JoinedPather {
	return JoinedPather{a, b}
}
