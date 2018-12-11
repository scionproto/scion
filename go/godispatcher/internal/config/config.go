// Copyright 2018 ETH Zurich
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

// Package config contains the configuration of the SCION dispatcher.
package config

import "github.com/scionproto/scion/go/lib/common"

type Config struct {
	// ID of the Dispatcher (required)
	ID string
}

func (cfg Config) Validate() error {
	if cfg.ID == "" {
		return common.NewBasicError("ID must be set", nil)
	}
	return nil
}
