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

const (
	DefaultLoggingFileSize   = 50
	DefaultLoggingFileMaxAge = 7
)

type Config struct {
	General General
	// Logging and metrics information.
	Logging Logging
}

// SetDefaults populates unset fields in cfg to their default values (if they
// have one).
func (cfg *Config) SetDefaults() {
	if cfg.Logging.File.Size == 0 {
		cfg.Logging.File.Size = DefaultLoggingFileSize
	}
	if cfg.Logging.File.MaxAge == 0 {
		cfg.Logging.File.MaxAge = DefaultLoggingFileMaxAge
	}
}

type General struct {
	// ID is the element ID.
	ID string
	// Bind is the local address to listen on for SCION messages.
	Bind string
	// Trust is the file path for the local trustdb.
	TrustDB string
	// Topology is the file path for the local topology JSON file.
	Topology string
}

type Logging struct {
	// File describes the output file for logging. If File.Level is unset, no
	// file logging is performed.
	File LogFile
	// Console describes how logging should be printed on standard output. If
	// Console.Level is unset, no console logging is performed.
	Console LogConsole
	// Metrics describes how the server outputs runtime metrics. Currently
	// supports Prometheus.
	Metrics Metrics
}

type LogFile struct {
	Path  string
	Level string
	// Max size of log file in MiB (default 50)
	Size uint
	// Max age of log file in days (default 7)
	MaxAge uint
	// How frequently to flush to the log file, in seconds
	FlushInterval int `toml:"flush_interval"`
}

type LogConsole struct {
	Level string
}

type Metrics struct {
	// Prometheus contains the address to export prometheus metrics on. If not
	// set, metrics are not exported.
	Prometheus string
}
