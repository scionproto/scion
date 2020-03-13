// Copyright 2019 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package egress

import (
	"io"

	"github.com/scionproto/scion/go/lib/fatal"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sigjson"
	"github.com/scionproto/scion/go/sig/egress/asmap"
	"github.com/scionproto/scion/go/sig/egress/iface"
	"github.com/scionproto/scion/go/sig/egress/reader"
)

func Init(tunIO io.ReadWriteCloser) {
	fatal.Check()
	iface.Init()
	// Spawn egress reader
	go func() {
		defer log.HandlePanic()
		reader.NewReader(tunIO).Run()
	}()
}

func ReloadConfig(cfg *sigjson.Cfg) bool {
	res := asmap.Map.ReloadConfig(cfg)
	log.Info("Config reloaded")
	return res
}
