// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config_test

import (
	"bytes"
	"testing"

	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/gateway/config"
	"github.com/scionproto/scion/go/pkg/gateway/config/configtest"
)

func TestGatewaySample(t *testing.T) {
	var sample bytes.Buffer
	var cfg config.Gateway
	cfg.Sample(&sample, nil, nil)

	configtest.InitGateway(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	configtest.CheckGateway(t, &cfg)
}

func TestTunnelSample(t *testing.T) {
	var sample bytes.Buffer
	var cfg config.Tunnel
	cfg.Sample(&sample, nil, nil)

	configtest.InitTunnel(&cfg)
	err := toml.NewDecoder(bytes.NewReader(sample.Bytes())).Strict(true).Decode(&cfg)
	assert.NoError(t, err)
	configtest.CheckTunnel(t, &cfg)
}

func TestDefaultAddress(t *testing.T) {
	testCases := map[string]struct {
		Input    string
		Expected string
	}{
		"valid": {
			Input:    "127.0.0.1:1337",
			Expected: "127.0.0.1:1337",
		},
		"valid, no port": {
			Input:    "127.0.0.1",
			Expected: "127.0.0.1:30256",
		},
		"valid, empty port": {
			Input:    "[::]:",
			Expected: "[::]:30256",
		},
		"hostname, zero port": {
			Input:    "gateway:0",
			Expected: "gateway:30256",
		},
		"empty": {
			Input:    "",
			Expected: ":30256",
		},
		"only port": {
			Input:    ":1337",
			Expected: ":1337",
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			addr := config.DefaultAddress(tc.Input, 30256)
			assert.Equal(t, tc.Expected, addr)
		})
	}
}
