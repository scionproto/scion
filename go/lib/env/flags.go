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
	"io/ioutil"
	"os"
)

var (
	config string
	sample string
)

// AddFlags adds the config and sample flags.
func AddFlags() {
	flag.StringVar(&config, "config", "", "Service TOML config file (required)")
	flag.StringVar(&sample, "sample", "",
		"Filename for creating a sample config. If set, the service is not started.")
}

// ConfigFile returns the config file path passed through the flag.
func ConfigFile() string {
	return config
}

// Usage returns a usage function based on the sample config.
func Usage(sampleConfig string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSample config file:\n%s", sampleConfig)
	}
}

// CheckFlags checks whether the config flag has been provided. In case it
// is not provided and the sample flag is not set, the usage message is printed.
// If the sample flag is set, a sample config is written to the specified file.
// The first return value is the return code of the program. The second value
// indicates whether the program can continue with its execution or should exit.
func CheckFlags(sampleConfig string) (int, bool) {
	if config == "" {
		if sample != "" {
			return writeSample(sampleConfig), false
		}
		fmt.Fprintln(os.Stderr, "Missing config file")
		flag.Usage()
		return 1, false
	}
	return 0, true
}

func writeSample(sampleConfig string) int {
	if err := ioutil.WriteFile(sample, []byte(sampleConfig), 0666); err != nil {
		fmt.Fprintln(os.Stderr, "Unable to write sample: "+err.Error())
		flag.Usage()
		return 1
	}
	fmt.Fprintln(os.Stdout, "Sample file written to: "+sample)
	return 0
}
