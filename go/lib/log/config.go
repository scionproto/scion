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
	"fmt"
	"io"

	"github.com/scionproto/scion/go/lib/config"
)

const (
	// DefaultConsoleLevel is the default log level for the console.
	DefaultConsoleLevel = "crit"
	// DefaultFileLevel is the defaul log level for files.
	DefaultFileLevel = "debug"
	// DefaultFileSizeMiB is the default rotation size in MiB.
	DefaultFileSizeMiB = 50
	// DefaultFileMaxAgeDays is the default rollover age in days.
	DefaultFileMaxAgeDays = 7
	// DefaultFileMaxBackups is the default maximum amount of file backups.
	DefaultFileMaxBackups = 10
	// DefaultFileFlushSeconds is the default amount of time between flushes.
	DefaultFileFlushSeconds uint = 5
)

// Config is the configuration for the logger.
type Config struct {
	config.NoValidator
	// File is the configuration for file logging.
	File FileConfig `toml:"file,omitempty"`
	// Console is the configuration for the console logging.
	Console ConsoleConfig `toml:"console,omitempty"`
}

// InitDefaults populates unset fields in cfg to their default values (if they
// have one).
func (c *Config) InitDefaults() {
	c.File.InitDefaults()
	c.Console.InitDefaults()
}

// Sample writes the sample configuration to the dst writer.
func (c *Config) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteSample(dst, path, nil,
		config.StringSampler{
			Text: fmt.Sprintf(loggingFileSample, ctx[config.ID]),
			Name: "file",
		},
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

// FileConfig is the configuration for the file logger.
type FileConfig struct {
	// Path is the location of the logging file. If unset, no file logging is
	// performed.
	Path string `toml:"path,omitempty"`
	// Level of file logging (defaults to DefaultFileLevel).
	Level string `toml:"level,omitempty"`
	// Size is the max size of log file in MiB (defaults to DefaultFileSizeMiB).
	Size uint `toml:"size,omitempty"`
	// MaxAge is the max age of log file in days (defaults to
	// DefaultFileMaxAgeDays).
	MaxAge uint `toml:"max_age,omitempty"`
	// MaxBackups is the max number of log files to retain (defaults to
	// DefaultFileMaxBackups).
	MaxBackups uint `toml:"max_backups,omitempty"`
	// FlushInterval specifies how frequently to flush to the log file, in
	// seconds (defaults to DefaultFileFlushSeconds).
	FlushInterval *uint `toml:"flush_interval,omitempty"`
	// Compress can be set to enable rotated file compression.
	Compress bool `toml:"compress,omitempty"`
}

// InitDefaults populates unset fields in cfg to their default values (if they
// have one).
func (c *FileConfig) InitDefaults() {
	if c.Level == "" {
		c.Level = DefaultFileLevel
	}
	if c.Size == 0 {
		c.Size = DefaultFileSizeMiB
	}
	if c.MaxAge == 0 {
		c.MaxAge = DefaultFileMaxAgeDays
	}
	if c.MaxBackups == 0 {
		c.MaxBackups = DefaultFileMaxBackups
	}
	if c.FlushInterval == nil {
		s := DefaultFileFlushSeconds
		c.FlushInterval = &s
	}
}

// ConsoleConfig is the config for the console logger.
type ConsoleConfig struct {
	// Level of console logging (defaults to DefaultConsoleLevel).
	Level string `toml:"level,omitempty"`
}

// InitDefaults populates unset fields in cfg to their default values (if they
// have one).
func (c *ConsoleConfig) InitDefaults() {
	if c.Level == "" {
		c.Level = DefaultConsoleLevel
	}
}
