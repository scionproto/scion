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
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beaconstorage"
	"github.com/scionproto/scion/go/lib/config"
)

func TestBeaconDBConfSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg beaconstorage.BeaconDBConf
	cfg.Sample(&sample, nil, map[string]string{config.ID: "test"})
	InitTestBeaconDBConf(&cfg)
	meta, err := toml.Decode(sample.String(), &cfg)
	require.NoError(t, err)
	assert.Empty(t, meta.Undecoded())
	CheckTestBeaconDBConf(t, &cfg, "test")
}
