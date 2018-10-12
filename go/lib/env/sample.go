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

// ConfigFlag adds a config flag.
func ConfigFlag() *string {
	return flag.String("config", "", "Service TOML config file (required)")
}

// SampleFlag adds a sample flag.
func SampleFlag() *string {
	return flag.String("sample", "",
		"Filename for creating a sample config. If set, the service is not started.")
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
func CheckFlags(flagConfig, flagSample, sampleConfig string) (int, bool) {
	if flagConfig == "" {
		if flagSample != "" {
			return writeSample(flagSample, sampleConfig), false
		}
		fmt.Fprintln(os.Stderr, "Missing config file")
		flag.Usage()
		return 1, false
	}
	return 0, true
}

func writeSample(flagSample, sampleConfig string) int {
	if err := ioutil.WriteFile(flagSample, []byte(sampleConfig), 0666); err != nil {
		fmt.Fprintln(os.Stderr, "Unable to write sample: "+err.Error())
		flag.Usage()
		return 1
	}
	fmt.Fprintln(os.Stdout, "Sample file written to: "+flagSample)
	return 0
}
