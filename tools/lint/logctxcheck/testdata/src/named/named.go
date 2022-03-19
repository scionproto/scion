// Copyright 2022 Anapaya Systems
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

package named

import (
	log "fake/lib/slog"

	slog "github.com/scionproto/scion/pkg/log"
)

func fakeImportIgnored() {
	log.Debug("message", nil)
	log.Info("message", "a")
	log.Error("messsage", nil)
}

func valid() {
	slog.Debug("message", "key")  // want `context should be even: len=1 ctx=\["key"\]`
	slog.Info("message", "key")   // want `context should be even: len=1 ctx=\["key"\]`
	slog.Error("messsage", "key") // want `context should be even: len=1 ctx=\["key"\]`
}
