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

package util_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/util"
)

func TestLowerKeys(t *testing.T) {
	t.Run("Nil map shouldn't do anything", func(t *testing.T) {
		var m map[string]string
		origMap := copyMap(m)
		util.LowerKeys(m)
		assert.Equal(t, origMap, m)
	})

	t.Run("Map with lowercase keys doesn't change", func(t *testing.T) {
		m := map[string]string{
			"key1": "val1",
			"key2": "val2",
		}
		origMap := copyMap(m)
		util.LowerKeys(m)
		assert.Equal(t, origMap, m)
	})
	t.Run("Map with mixed keys changes", func(t *testing.T) {
		m := map[string]string{
			"Key1": "val1",
			"kEy2": "val2",
			"key3": "val3",
		}
		util.LowerKeys(m)
		expectedM := map[string]string{
			"key1": "val1",
			"key2": "val2",
			"key3": "val3",
		}
		assert.Equal(t, expectedM, m)
	})

}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
