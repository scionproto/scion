// Copyright 2019 ETH Zurich
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

package pathpol

import (
	"encoding/json"
	"strings"

	"github.com/scionproto/scion/go/lib/spath/spathmeta"
)

// Sequence is a list of path interfaces that a path should match
type Sequence []*HopPredicate

// NewSequence creates a new sequence from a list of string tokens
func NewSequence(tokens []string) (Sequence, error) {
	s := make(Sequence, 0)
	for _, token := range tokens {
		if token == "" {
			continue
		}
		hp, err := HopPredicateFromString(token)
		if err != nil {
			return nil, err
		}
		s = append(s, hp)
	}
	return s, nil
}

// Eval evaluates the interface sequence list and returns the set of paths that match the list
func (s Sequence) Eval(inputSet spathmeta.AppPathSet) spathmeta.AppPathSet {
	if len(s) == 0 {
		return inputSet
	}

	resultSet := make(spathmeta.AppPathSet)
	for key, path := range inputSet {
		if pathMatches(path.Entry.Path.Interfaces, s) {
			resultSet[key] = path
		}
	}
	return resultSet
}

func (s *Sequence) String() string {
	str := ""
	for i, hp := range *s {
		if i != 0 {
			str += " "
		}
		str += hp.String()
	}
	return str
}

func (s *Sequence) LoadFromString(str string) error {
	parts := strings.Split(str, " ")
	sn := Sequence{}
	for _, hpStr := range parts {
		if len(hpStr) == 0 {
			continue
		}
		hp, err := HopPredicateFromString(hpStr)
		if err != nil {
			return err
		}
		sn = append(sn, hp)
	}
	*s = sn
	return nil
}

func (s *Sequence) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Sequence) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}
	return s.LoadFromString(str)
}
