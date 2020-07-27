// Copyright 2018 ETH Zurich
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

package iface

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/snet"
)

// A SessPath contains a path and metadata related to path health.
type SessPath struct {
	key  snet.PathFingerprint
	path snet.Path
}

func NewSessPath(key snet.PathFingerprint, path snet.Path) *SessPath {
	return &SessPath{key: key, path: path}
}

func (sp *SessPath) Key() snet.PathFingerprint {
	return sp.key
}

func (sp *SessPath) Path() snet.Path {
	return sp.path
}

func (sp *SessPath) IsCloseToExpiry() bool {
	metadata := sp.Path().Metadata()
	return metadata == nil || metadata.Expiry().Before(time.Now().Add(SafetyInterval))
}

func (sp *SessPath) Copy() *SessPath {
	if sp == nil {
		return nil
	}
	return &SessPath{
		key:  sp.key,
		path: sp.path.Copy(),
	}
}

func (sp *SessPath) String() string {
	return fmt.Sprintf("Key: %s %s", sp.key[:8], sp.path)
}
