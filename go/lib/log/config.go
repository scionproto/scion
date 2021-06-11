// Copyright 2018 ETH Zurich, Anapaya Systems
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

package log

import (
	"io"
	"strings"

	"github.com/scionproto/scion/go/lib/config"
)

const (
	// DefaultConsoleLevel is the default log level for the console.
	DefaultConsoleLevel = "info"
	// DefaultStacktraceLevel is the default log level for which stack traces are included.
	DefaultStacktraceLevel = "error"
)

// Config is the configuration for the logger.
type Config struct {
	config.NoValidator
	// Console is the configuration for the console logging.
	Console ConsoleConfig `toml:"console,omitempty"`
}

// InitDefaults populates unset fields in cfg to their default values (if they
// have one).
func (c *Config) InitDefaults() {
	c.Console.InitDefaults()
}

// Sample writes the sample configuration to the dst writer.
func (c *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, nil,
		config.StringSampler{
			Text: loggingConsoleSample,
			Name: "console",
		},
	)
}

// ConfigName returns the name this config should have in a struct embedding
// this.
func (c *Config) ConfigName() string {
	return "log"
}

// ConsoleConfig is the config for the console logger.
type ConsoleConfig struct {
	// Level of console logging (defaults to DefaultConsoleLevel).
	Level string `toml:"level,omitempty"`
	// Format of the console logging. (human|json)
	Format string `toml:"format,omitempty"`
	// StacktraceLevel sets from which level stacktraces are included.
	StacktraceLevel string `toml:"stacktrace_level,omitempty"`
	// DisableCaller stops annotating logs with the calling function's file
	// name and line number. By default, all logs are annotated.
	DisableCaller bool `toml:"disable_caller,omitempty"`
}

// InitDefaults populates unset fields in cfg to their default values (if they
// have one).
func (c *ConsoleConfig) InitDefaults() {
	if c.Level == "" {
		c.Level = DefaultConsoleLevel
	}
	if !strings.EqualFold(c.Format, "json") {
		c.Format = "human"
	}
	if c.StacktraceLevel == "" {
		c.StacktraceLevel = DefaultStacktraceLevel
	}
}
