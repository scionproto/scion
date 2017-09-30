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

// Package util contains general utility functions
package util

// PadOffset returns the next integer larger than x that is aligned to align.
func PadOffset(x, align int) int {
	return x + (align-(x%align))%align
}

// IntMin returns the minimum of two integer.
func IntMin(x, y int) int {
	if x <= y {
		return x
	}
	return y
}
