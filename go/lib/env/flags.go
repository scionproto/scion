// Copyright 2018 Anapaya Systems
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
	"flag"
	"fmt"
	"os"
)

var (
	config     string
	helpConfig bool
	version    bool
)

// AddFlags adds the config and sample flags.
func AddFlags() {
	flag.StringVar(&config, "config", "", "TOML config file.")
	flag.BoolVar(&helpConfig, "help-config", false, "Output sample commented config file.")
	flag.BoolVar(&version, "version", false, "Output version information and exit.")
}

// ConfigFile returns the config file path passed through the flag.
func ConfigFile() string {
	return config
}

// Usage outputs run-time help to stdout.
func Usage() {
	fmt.Printf("Usage: %s -config <FILE> \n   or: %s -help-config\n\nArguments:\n",
		os.Args[0], os.Args[0])
	flag.CommandLine.SetOutput(os.Stdout)
	flag.PrintDefaults()
}

// CheckFlags checks whether the config or help-config flags have been set. In case the
// help-config flag is set, the config flag is ignored and a commented sample config
// is written to stdout.
//
// The first return value is the return code of the program. The second value
// indicates whether the program can continue with its execution or should exit.
func CheckFlags(sampleConfig string) (int, bool) {
	if helpConfig {
		fmt.Print(sampleConfig)
		return 0, false
	}
	if version {
		fmt.Printf(VersionInfo())
		return 0, false
	}
	if config == "" {
		fmt.Fprintln(os.Stderr, "Err: Missing config file")
		flag.Usage()
		return 1, false
	}
	return 0, true
}
