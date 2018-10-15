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
	config string
	sample bool
)

// AddFlags adds the config and sample flags.
func AddFlags() {
	flag.StringVar(&config, "config", "", "Service TOML config file.")
	flag.BoolVar(&sample, "help-config", false, "Write sample config file.")
}

// ConfigFile returns the config file path passed through the flag.
func ConfigFile() string {
	return config
}

// Usage returns a usage function based on the sample config.
func Usage(sampleConfig string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -config <FILE> \n   or: %s -help-config\n\nArguments:\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
}

// CheckFlags checks whether the config flag has been provided. In case it
// is not provided and the sample flag is not set, the usage message is printed.
// If the sample flag is set, a sample config is written to the specified file.
// The first return value is the return code of the program. The second value
// indicates whether the program can continue with its execution or should exit.
func CheckFlags(sampleConfig string) (int, bool) {
	if config == "" {
		if sample {
			fmt.Fprint(os.Stdout, sampleConfig)
			return 0, false
		}
		fmt.Fprint(os.Stderr, "Err: Missing config file\n\n")
		flag.Usage()
		return 1, false
	}
	return 0, true
}
