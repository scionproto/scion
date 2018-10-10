// Copyright 2018 ETH Zurich, Anapaya Systems
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

package env

import (
	"time"

	"github.com/BurntSushi/toml"

	"github.com/scionproto/scion/go/lib/util"
)

var _ (toml.TextUnmarshaler) = (*Duration)(nil)
var _ (toml.TextMarshaler) = (*Duration)(nil)

// Duration enables parsing of durations formatted as described in util.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = util.ParseDuration(string(text))
	return err
}

func (d *Duration) MarshalText() (text []byte, err error) {
	return []byte(util.FmtDuration(d.Duration)), nil
}
