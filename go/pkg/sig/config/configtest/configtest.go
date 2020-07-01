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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/sig/config"
)

func CheckTestSIG(t *testing.T, cfg *config.SigConf, id string) {
	assert.Equal(t, id, cfg.ID)
	assert.Equal(t, "/etc/scion/sig/sig.json", cfg.SIGConfig)
	assert.Equal(t, xtest.MustParseIA("1-ff00:0:113"), cfg.IA)
	assert.Equal(t, net.ParseIP("192.0.2.100"), cfg.IP)
	assert.Equal(t, config.DefaultCtrlPort, int(cfg.CtrlPort))
	assert.Equal(t, config.DefaultEncapPort, int(cfg.EncapPort))
	assert.Equal(t, config.DefaultTunName, cfg.Tun)
	assert.Equal(t, config.DefaultTunRTableId, cfg.TunRTableId)
}
