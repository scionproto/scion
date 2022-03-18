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

package mgmtapi_test

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"

	api "github.com/scionproto/scion/private/mgmtapi"
	apitest "github.com/scionproto/scion/private/mgmtapi/mgmtapitest"
)

func TestConfigSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg api.Config
	cfg.Sample(&sample, nil, nil)
	apitest.InitConfig(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	apitest.CheckConfig(t, &cfg)
}
