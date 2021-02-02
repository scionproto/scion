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

package apitest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/api"
)

// InitConfig prepares the api config for testing.
func InitConfig(cfg *api.Config) {
	cfg.Addr = "8.8.8.8:8080"
}

// CheckConfig checks that the given config matches the sample values.
func CheckConfig(t *testing.T, cfg *api.Config) {
	assert.Empty(t, cfg.Addr)
}
