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

package pathstoragetest

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/pathstorage"
)

func TestPathDBConfSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg pathstorage.PathDBConf
	cfg.Sample(&sample, nil, map[string]string{config.ID: "test"})
	InitTestPathDBConf(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	CheckTestPathDBConf(t, &cfg, "test")
}

func TestRevCacheConfSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg pathstorage.RevCacheConf
	cfg.Sample(&sample, nil, map[string]string{config.ID: "test"})
	InitTestRevCacheConf(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	CheckTestRevCacheConf(t, &cfg)
}
