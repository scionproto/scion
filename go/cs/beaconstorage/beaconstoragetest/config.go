// Copyright 2019 Anapaya Systems
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

package beaconstoragetest

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/cs/beaconstorage"
	"github.com/scionproto/scion/go/lib/infra/modules/db"
	"github.com/scionproto/scion/go/lib/util"
)

// InitTestBeaconDBConf initializes the config with values that should be
// overwritten during parsing.
func InitTestBeaconDBConf(cfg *beaconstorage.BeaconDBConf) {
	if *cfg == nil {
		*cfg = make(beaconstorage.BeaconDBConf)
	}
	(*cfg)[db.MaxOpenConnsKey] = "maxOpenConns"
	(*cfg)[db.MaxIdleConnsKey] = "maxIdleConns"
}

// CheckTestBeaconDBConf checks that the values are as expected from the sample.
func CheckTestBeaconDBConf(t *testing.T, cfg *beaconstorage.BeaconDBConf, id string) {
	util.LowerKeys(*cfg)
	assert.False(t, isSet(cfg.MaxOpenConns()))
	assert.False(t, isSet(cfg.MaxIdleConns()))
	assert.Equal(t, beaconstorage.BackendSqlite, cfg.Backend())
	assert.Equal(t, fmt.Sprintf("/var/lib/scion/beacondb/%s.beacon.db", id), cfg.Connection())
}

func isSet(_ int, set bool) bool {
	return set
}
