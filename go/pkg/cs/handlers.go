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

package cs

import (
	"github.com/scionproto/scion/go/lib/infra"
)

type HandlerRegistry interface {
	AddHandler(infra.MessageType, infra.Handler)
}

// MultiRegister is a convenience function to register a handler with multiple
// registries.
func MultiRegister(msgType infra.MessageType, handler infra.Handler, regs ...HandlerRegistry) {
	for _, reg := range regs {
		reg.AddHandler(msgType, handler)
	}
}
