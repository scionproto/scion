// Copyright 2018 ETH Zurich
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

package env

import (
	"path/filepath"

	"github.com/scionproto/scion/go/lib/log"
)

type Logging struct {
	File struct {
		// Path is the location of the logging file. If unset, no file logging
		// is performed.
		Path string
		// Level of file logging (defaults to DefaultLoggingLevel).
		Level string
		// Size is the max size of log file in MiB (defaults to DefaultLoggingFileSize)
		Size uint
		// Max age of log file in days (defaults to DefaultLoggingFileMaxAge)
		MaxAge uint
		// FlushInterval specifies how frequently to flush to the log file,
		// in seconds
		FlushInterval int
	}

	Console struct {
		// Level of console logging. If unset, no console logging is
		// performed.
		Level string
	}
}

// setDefaults populates unset fields in cfg to their default values (if they
// have one).
func (cfg *Logging) setDefaults() {
	if cfg.File.Size == 0 {
		cfg.File.Size = DefaultLoggingFileSize
	}
	if cfg.File.MaxAge == 0 {
		cfg.File.MaxAge = DefaultLoggingFileMaxAge
	}
	if cfg.File.Level == "" {
		cfg.File.Level = DefaultLoggingLevel
	}
}

// InitLogging initializes logging and sets the root logger Log.
func InitLogging(cfg *Logging) error {
	if err := setupFileLogging(cfg); err != nil {
		return err
	}
	if err := setupConsoleLogging(cfg); err != nil {
		return err
	}
	return nil
}

func setupFileLogging(cfg *Logging) error {
	if cfg.File.Path != "" {
		return log.SetupLogFile(
			filepath.Base(cfg.File.Path),
			filepath.Dir(cfg.File.Path),
			cfg.File.Level,
			int(cfg.File.Size),
			int(cfg.File.MaxAge),
			int(cfg.File.FlushInterval),
		)
	}
	return nil
}

func setupConsoleLogging(cfg *Logging) error {
	if cfg.Console.Level != "" {
		return log.SetupLogConsole(cfg.Console.Level)
	}
	return nil
}
