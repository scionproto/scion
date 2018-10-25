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
		// Level of file logging (defaults to lib/log default).
		Level string
		// Size is the max size of log file in MiB (defaults to lib/log default).
		Size uint
		// Max age of log file in days (defaults to lib/log default).
		MaxAge uint
		// FlushInterval specifies how frequently to flush to the log file,
		// in seconds (defaults to lib/log default).
		FlushInterval *int
	}

	Console struct {
		// Level of console logging (defaults to lib/log default).
		Level string
	}
}

// setDefaults populates unset fields in cfg to their default values (if they
// have one).
func (cfg *Logging) setDefaults() {
	if cfg.Console.Level == "" {
		cfg.Console.Level = log.DefaultConsoleLevel
	}
	if cfg.File.Level == "" {
		cfg.File.Level = log.DefaultFileLevel
	}
	if cfg.File.Size == 0 {
		cfg.File.Size = log.DefaultFileSizeMiB
	}
	if cfg.File.MaxAge == 0 {
		cfg.File.MaxAge = log.DefaultFileMaxAgeDays
	}
	if cfg.File.FlushInterval == nil {
		s := log.DefaultFileFlushSeconds
		cfg.File.FlushInterval = &s
	}
}

// InitLogging initializes logging and sets the root logger Log.
func InitLogging(cfg *Logging) error {
	cfg.setDefaults()
	if err := setupFileLogging(cfg); err != nil {
		return err
	}
	if err := log.SetupLogConsole(cfg.Console.Level); err != nil {
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
			*cfg.File.FlushInterval,
		)
	}
	return nil
}

// LogSvcStarted should be called by services as soon as logging is initialized.
func LogSvcStarted(svcType, elemId string) {
	log.Info("=====================> Service started", "svc", svcType, "id", elemId)
}

// CleanupLog calls log.LogPanicAndExit and log.Flush
// it is mainly a helper to have a single defer call in services.
func CleanupLog() {
	log.LogPanicAndExit()
	log.Flush()
}
