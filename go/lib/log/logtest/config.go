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

package logtest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
)

// InitTestLogging prepares the config for testing.
func InitTestLogging(cfg *log.Config) {
	cfg.Console.DisableCaller = true
}

// CheckTestLogging checks that the given config matches the sample values.
func CheckTestLogging(t *testing.T, cfg *log.Config, id string) {
	assert.Equal(t, log.DefaultConsoleLevel, cfg.Console.Level)
	assert.Equal(t, "human", cfg.Console.Format)
	assert.Equal(t, log.DefaultStacktraceLevel, cfg.Console.StacktraceLevel)
	assert.False(t, cfg.Console.DisableCaller)
}
