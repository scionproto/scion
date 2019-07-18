// Copyright 2019 Anapaya Systems
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

package envtest

import (
	"bytes"
	"testing"

	"github.com/BurntSushi/toml"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/config"
	"github.com/scionproto/scion/go/lib/env"
)

func TestGeneralSample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg env.General
		cfg.Sample(&sample, nil, map[string]string{config.ID: "general"})
		InitTestGeneral(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		CheckTestGeneral(&cfg, "general")
	})
}

func TestLoggingSample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg env.Logging
		cfg.Sample(&sample, nil, map[string]string{config.ID: "logging"})
		InitTestLogging(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		CheckTestLogging(&cfg, "logging")
	})
}

func TestMetricsSample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg env.Metrics
		cfg.Sample(&sample, nil, nil)
		InitTestMetrics(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		CheckTestMetrics(&cfg)
	})
}

func TestTracingSample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg env.Tracing
		cfg.Sample(&sample, nil, nil)
		InitTestTracing(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		CheckTestTracing(&cfg)
	})
}

func TestSciondClientSample(t *testing.T) {
	Convey("Sample correct", t, func() {
		var sample bytes.Buffer
		var cfg env.SciondClient
		cfg.Sample(&sample, nil, nil)
		InitTestSciond(&cfg)
		meta, err := toml.Decode(sample.String(), &cfg)
		SoMsg("err", err, ShouldBeNil)
		SoMsg("unparsed", meta.Undecoded(), ShouldBeEmpty)
		InitTestSciond(&cfg)
	})
}
