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

var s struct {
	logger log.Logger
}

func validParity() {
	log.Debug("message")
	log.Info("message")
	log.Error("message")

	log.Debug("message", "key", value)
	log.Info("message", "key", value)
	log.Error("message", "key", value)

	log.Debug("message", "key", value, "key1", value)
	log.Info("message", "key", value, "key1", value)
	log.Error("message", "key", value, "key1", value)
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

	log.Debug("message", "key", value, "key1") // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	log.Info("message", "key", value, "key1")  // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	log.Error("message", "key", value, "key1") // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
}

func invalidType() {
	log.Info("message", value, value) // want `key should be string: type="int" name="value"`
}

func loggerNew() {
	log.New()
	log.New("key", value)
	log.New("key", value, "key1", value)
	log.New("key")                      // want `context should be even: len=1 ctx=\["key"\]`
	log.New("key", value, "key1")       // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	log.New("key", value, "key", value) // want `duplicate key in context:`

	loggerN := log.New()
	loggerN.New()
	loggerN.New("key", value)
	loggerN.New("key", value, "key1", value)
	loggerN.New("key")                      // want `context should be even: len=1 ctx=\["key"\]`
	loggerN.New("key", value, "key1")       // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	loggerN.New("key", value, "key", value) // want `duplicate key in context:`

	loggerC := log.FromCtx(context.Background())
	loggerC.New()
	loggerC.New("key", value)
	loggerC.New("key", value, "key1", value)
	loggerC.New("key")                      // want `context should be even: len=1 ctx=\["key"\]`
	loggerC.New("key", value, "key1")       // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	loggerC.New("key", value, "key", value) // want `duplicate key in context:`

	s.logger.New()
	s.logger.New("key", value)
	s.logger.New("key", value, "key1", value)
	s.logger.New("key")                      // want `context should be even: len=1 ctx=\["key"\]`
	s.logger.New("key", value, "key1")       // want `context should be even: len=3 ctx=\["key",value,"key1"\]`
	s.logger.New("key", value, "key", value) // want `duplicate key in context:`
}

func loggerLog() {
	loggerC := log.FromCtx(context.Background())
	loggerC.Info("message", "key")                           // want `context should be even: len=1 ctx=\["key"\]`
	log.FromCtx(context.Background()).Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`

	loggerN := log.New()
	loggerN.Info("message", "key")   // want `context should be even: len=1 ctx=\["key"\]`
	log.New().Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`

	loggerR := log.Root()
	loggerR.Info("message", "key")    // want `context should be even: len=1 ctx=\["key"\]`
	log.Root().Info("message", "key") // want `context should be even: len=1 ctx=\["key"\]`
}

type key string
