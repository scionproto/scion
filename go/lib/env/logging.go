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
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
)

// Startup* variables are set during link time.
var (
	StartupBuildDate  string = "local builds have no build time"
	StartupVersion    string
	StartupBuildChain string
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
		// MaxAge is the max age of log file in days (defaults to lib/log default).
		MaxAge uint
		// MaxBackups is the max number of log files to retain (defaults to lib/log default).
		MaxBackups uint
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
	if cfg.File.MaxBackups == 0 {
		cfg.File.MaxBackups = log.DefaultFileMaxBackups
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
			int(cfg.File.MaxBackups),
			*cfg.File.FlushInterval,
		)
	}
	return nil
}

// LogAppStarted should be called by applications as soon as logging is
// initialized.
func LogAppStarted(svcType, elemId string) error {
	inDocker, err := RunsInDocker()
	if err != nil {
		return common.NewBasicError("Unable to determine if running in docker", err)
	}
	info := fmt.Sprintf("=====================> Service started %s %s\n"+
		"%s  %s\n  %s\n  %s\n  %s\n",
		svcType,
		elemId,
		VersionInfo(),
		fmt.Sprintf("In docker:     %v", inDocker),
		fmt.Sprintf("pid:           %d", os.Getpid()),
		fmt.Sprintf("euid/egid:     %d %d", os.Geteuid(), os.Getegid()),
		fmt.Sprintf("cmd line:      %q", os.Args),
	)
	log.Info(info)
	return nil
}

// VersionInfo returns build version information (build date, build version, build chain).
func VersionInfo() string {
	return fmt.Sprintf("  %s\n  %s\n  %s\n",
		fmt.Sprintf("Build date:    %s", StartupBuildDate),
		fmt.Sprintf("Scion version: %s", StartupVersion),
		fmt.Sprintf("Build chain:   %s", StartupBuildChain),
	)
}

func LogAppStopped(svcType, elemId string) {
	log.Info(fmt.Sprintf("=====================> Service stopped %s %s", svcType, elemId))
}
