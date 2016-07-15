// Copyright 2016 ETH Zurich
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

import (
	"fmt"
	"strconv"
	"strings"
)

type ISD_AS struct {
	isd, as int
}

func (ia ISD_AS) String() string {
	return fmt.Sprintf("%d-%d", ia.isd, ia.as)
}

func (ia *ISD_AS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return fmt.Errorf("Invalid ISD-AS %q", s)
	}
	isd, err := strconv.Atoi(parts[0])
	if err != nil {
		e := err.(*strconv.NumError)
		return fmt.Errorf("Unable to parse ISD from %q: %v", s, e.Err)
	}
	as, err := strconv.Atoi(parts[1])
	if err != nil {
		e := err.(*strconv.NumError)
		return fmt.Errorf("Unable to parse AS from %q: %v", s, e.Err)
	}
	ia.isd = isd
	ia.as = as
	return nil
}
