// Copyright 2020 Anapaya Systems
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

package config

import (
	"io"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/private/config"
)

const defaultExpiration = time.Minute

type Config struct {
	config.NoValidator
	Cache Cache `toml:"cache"`
}

func (cfg *Config) InitDefaults() {
	config.InitAll(
		&cfg.Cache,
	)
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, ctx,
		&cfg.Cache,
	)
}

func (cfg *Config) ConfigName() string {
	return "trustengine"
}

type Cache struct {
	Disable    bool         `toml:"disable,omitempty"`
	Expiration util.DurWrap `toml:"expiration,omitempty"`
}

func (cfg *Cache) New() *cache.Cache {
	if cfg.Disable {
		return nil
	}
	return cache.New(cfg.Expiration.Duration, time.Minute)
}

func (cfg *Cache) InitDefaults() {
	if cfg.Expiration.Duration == 0 {
		cfg.Expiration.Duration = defaultExpiration
	}
}

func (cfg *Cache) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, `
# Disable caching.
disable = false

# Maximum cache expiration.
expiration = "1m"
`)
}

func (cfg *Cache) ConfigName() string {
	return "cache"
}
