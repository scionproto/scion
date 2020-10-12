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

package env

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/config"
)

func TestAllFeatureFlagsShouldBeBoolean(t *testing.T) {
	features := reflect.TypeOf(Features{})
	for i := 0; i < features.NumField(); i++ {
		switch features.Field(i).Type {
		case reflect.TypeOf(config.NoDefaulter{}), reflect.TypeOf(config.NoValidator{}):
		default:
			assert.Equal(t, reflect.Bool, features.Field(i).Type.Kind())
		}
	}
}
