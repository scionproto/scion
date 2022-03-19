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

package fail

import (
	"context"

	"github.com/scionproto/scion/pkg/log"
)

const (
	untyped     = "untyped_key"
	typed   key = "typed_key"
)

var value = 1

func validParity() {
	log.Debug("message")
	log.Info("message")
	log.Error("message")

	log.Debug("message")
	log.Info("message")
	log.Error("message")

	log.Debug("message", "key", value)
	log.Info("message", "key", value)
	log.Error("message", "key", value)

	log.Debug("message", "key", value, "key", value)
	log.Info("message", "key", value, "key", value)
	log.Error("message", "key", value, "key", value)
}

func validTypes() {
	log.Debug("message", "key", value)
	log.Debug("message", untyped, value)
	log.Debug("message", typed, value)
}

func invalidParity() {
	log.Debug("message", "key") // want `context should be even: len=1 ctx=\["key"\]`
	log.Info("message", "key")  // want `context should be even: len=1 ctx=\["key"\]`
	log.Error("message", "key") // want `context should be even: len=1 ctx=\["key"\]`

	log.Debug("message", "key", value, "key") // want `context should be even: len=3 ctx=\["key",value,"key"\]`
	log.Info("message", "key", value, "key")  // want `context should be even: len=3 ctx=\["key",value,"key"\]`
	log.Error("message", "key", value, "key") // want `context should be even: len=3 ctx=\["key",value,"key"\]`
}

func invalidType() {
	log.Info("message", value, value) // want `key should be string: type="int" name="value"`
}

func logger() {
	logger := log.FromCtx(context.Background())
	loggerN := log.New()
	loggerR := log.Root()
	logger.Info("message", "key")  // want `context should be even: len=1 ctx=\["key"\]`
	loggerN.Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`
	loggerR.Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`

	log.FromCtx(context.Background()).Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`
	log.New().Info("message", "key")                         // want `context should be even: len=1 ctx=\["key"\]`
	log.Root().Info("message", "key")                        // want `context should be even: len=1 ctx=\["key"\]`
}

type key string
