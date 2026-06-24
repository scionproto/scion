// Copyright 2026 Anapaya Systems
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

package prism

import (
	"encoding/json"

	"gopkg.in/yaml.v3"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// EncodeYAML renders the config as YAML.
func (c Config) EncodeYAML() ([]byte, error) {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return nil, serrors.Wrap("encoding prism config to YAML", err)
	}
	return raw, nil
}

// EncodeJSON renders the config as indented JSON.
func (c Config) EncodeJSON() ([]byte, error) {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, serrors.Wrap("encoding prism config to JSON", err)
	}
	return raw, nil
}

// DecodeYAML parses a config from YAML.
func DecodeYAML(raw []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Config{}, serrors.Wrap("decoding prism config from YAML", err)
	}
	return c, nil
}

// DecodeJSON parses a config from JSON.
func DecodeJSON(raw []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return Config{}, serrors.Wrap("decoding prism config from JSON", err)
	}
	return c, nil
}
