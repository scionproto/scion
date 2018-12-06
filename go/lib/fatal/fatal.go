// Copyright 2018 Anapaya Systems
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

// Package fatal deals with delivering fatal error conditions to the main
// goroutine. The goroutine can then perform clean shutdown.
package fatal

var (
	fatalC chan error
)

// Initialize the package.
func init() {
	fatalC = make(chan error)
}

// Signal that the application should shut down.
func Fatal(err error) {
	fatalC <- err
}

// Get access to the underlying channel. This is used by main goroutine to wait for fatal errors.
func Chan() chan error {
	return fatalC
}
