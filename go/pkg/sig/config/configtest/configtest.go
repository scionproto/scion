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

package configtest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/pkg/sig/config"
)

func InitGateway(cfg *config.Gateway) {
	cfg.Dispatcher = "garbage"
}

func CheckGateway(t *testing.T, cfg *config.Gateway) {
	assert.Equal(t, "gateway", cfg.ID)
	assert.Equal(t, config.DefaultTrafficPolicyFile, cfg.TrafficPolicy)
	assert.Equal(t, config.DefaultCtrlAddr, cfg.CtrlAddr)
	assert.Equal(t, config.DefaultDataAddr, cfg.DataAddr)
	assert.Empty(t, cfg.Dispatcher)
}

func InitTunnel(cfg *config.Tunnel) {}

func CheckTunnel(t *testing.T, cfg *config.Tunnel) {
	assert.Equal(t, config.DefaultTunnelName, cfg.Name)
	assert.Equal(t, config.DefaultTunnelRoutingTableID, cfg.RoutingTableID)
}
