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

package empty

// PathLen is the length of a serialized empty path in bytes
const PathLen = 0

// Path encodes an empty path. An empty path is a special path that takes zero
// bytes on the wire and is used for AS internal communication.
type Path struct{}

func (o Path) DecodeFromBytes(_ []byte) error {
	return nil
}

func (o Path) SerializeTo(b []byte) error {
	return nil
}

func (o Path) Reverse() error {
	return nil
}

func (o Path) Len() int {
	return PathLen
}
