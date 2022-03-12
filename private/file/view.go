// Copyright 2021 Anapaya Systems
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

// Package file contains utility functions for interacting with files.
package file

// View maintains a cached concurrency-safe view of an object.
//
// Use Get to get a reference to the object.
type View interface {
	// Get returns a reference to the cached object. Get is safe for concurrent use.
	//
	// Get guarantees that once an object is returned, it will no longer be modified by
	// View internals.
	//
	// However, Get implementations are free to return different objects or
	// return references to the same object, so callers should not assume
	// they see the same object across different calls.
	Get() (interface{}, error)
}
