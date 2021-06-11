// Copyright 2021 Anapaya Systems
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

package certs

import (
	"github.com/opentracing/opentracing-go"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
)

func setupTracer(componentName, agent string) (func(), error) {
	if len(agent) == 0 {
		return func() {}, nil
	}
	cfg := &env.Tracing{
		Enabled: true,
		Debug:   true,
		Agent:   agent,
	}
	cfg.InitDefaults()
	tr, closer, err := cfg.NewTracer(componentName)
	if err != nil {
		return nil, err
	}
	opentracing.SetGlobalTracer(tr)
	closeTracer := func() {
		if err := closer.Close(); err != nil {
			log.Error("Unable to close tracer", "err", err)
		}
	}
	return closeTracer, nil
}
