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
	"io"
	"os"
)

var (
	config     string
	helpConfig bool
)

// AddFlags adds the config and sample flags.
func AddFlags() {
	flag.StringVar(&config, "config", "", "Service TOML config file.")
	flag.BoolVar(&helpConfig, "help-config", false, "Output sample commented config file.")
}

// ConfigFile returns the config file path passed through the flag.
func ConfigFile() string {
	return config
}

// Usage returns a usage function which writes to the provided writer.
func Usage(out io.Writer) func() {
	return func() {
		fmt.Fprintf(out, "Usage: %s -config <FILE> \n   or: %s -help-config\n\nArguments:\n",
			os.Args[0], os.Args[0])
		flag.CommandLine.SetOutput(out)
		flag.PrintDefaults()
	}
}

// CheckFlags checks whether the config or help-config flags have been set. In case the
// help-config flag is set, the config flag is ignored and a commented sample config
// is written to stdout. If help-config and config are not set, the usage message is
// written to stderr.
//
// The first return value is the return code of the program. The second value
// indicates whether the program can continue with its execution or should exit.
func CheckFlags(sampleConfig string) (int, bool) {
	if helpConfig {
		fmt.Print(sampleConfig)
		return 0, false
	}
	if config == "" {
		fmt.Fprint(os.Stderr, "Err: Missing config file\n\n")
		Usage(os.Stderr)()
		return 1, false
	}
	return 0, true
}
