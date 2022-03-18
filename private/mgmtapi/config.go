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

package mgmtapi

import (
	"io"

	"github.com/scionproto/scion/private/config"
)

const apiSample = `
# The address to expose the API on (host:port or ip:port).
# If not set, the API is not exposed.
addr = ""
`

type Config struct {
	config.NoDefaulter
	config.NoValidator
	Addr string `toml:"addr,omitempty"`
}

func (cfg *Config) Sample(dst io.Writer, path config.Path, _ config.CtxMap) {
	config.WriteString(dst, apiSample)
}

func (cfg *Config) ConfigName() string {
	return "api"
}
