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

package idiscoverytest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/infra/modules/idiscovery"
)

func InitTestConfig(cfg *idiscovery.Config) {
	cfg.Dynamic.Enable = true
	cfg.Dynamic.Https = true
	cfg.Static.Enable = true
	cfg.Static.Https = true
	cfg.Static.Filename = "topology.json"
}

func CheckTestConfig(t *testing.T, cfg *idiscovery.Config) {
	t.Run("static", func(t *testing.T) {
		checkCommon(t, cfg.Static.FetchConfig)
		assert.Empty(t, cfg.Static.Filename)
	})
	t.Run("dynamic", func(t *testing.T) {
		checkCommon(t, cfg.Dynamic)
	})
}

func checkCommon(t *testing.T, cfg idiscovery.FetchConfig) {
	assert.False(t, cfg.Enable)
	assert.Equal(t, idiscovery.DefaultFetchTimeout, cfg.Timeout.Duration)
	assert.False(t, cfg.Https)
	assert.Equal(t, idiscovery.DefaultInitialConnectPeriod, cfg.Connect.InitialPeriod.Duration)
	assert.Equal(t, idiscovery.FailActionContinue, cfg.Connect.FailAction)
}
