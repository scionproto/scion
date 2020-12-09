// Copyright 2020 Anapaya Systems
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

package app

import (
	"github.com/scionproto/scion/go/lib/log"
)

// LogLevelUsage defines the usage text for the log.level flag.
const LogLevelUsage = "Console logging level verbosity (debug|info|error)"

// SetupLog sets up the logging for a consol application.
func SetupLog(level string) error {
	if len(level) == 0 || level == "none" {
		return nil
	}
	return log.Setup(log.Config{
		Console: log.ConsoleConfig{
			Level:           level,
			StacktraceLevel: "none",
		},
	})
}
