// Copyright 2022 Anapaya Systems
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

package addr

// Match matches the input ISD-AS if both the ISD and the AS number are the same
// as the one of the matcher. Zero values of ISD and AS in the matchers ISD-AS
// are treated as wildcards and match everything.
func (m IA) IAMatcher(ia IA) bool {
	switch {
	case m.IsZero():
		return true
	case m.ISD() == 0:
		return m.AS() == ia.AS()
	case m.AS() == 0:
		return m.ISD() == ia.ISD()
	default:
		return m.Equal(ia)
	}
}
