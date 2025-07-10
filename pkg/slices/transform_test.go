// Copyright 2025 Anapaya Systems
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

package slices_test

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/pkg/slices"
)

func TestTransform(t *testing.T) {
	t.Parallel()

	t.Run("nil slice", func(t *testing.T) {
		t.Parallel()

		var in []int
		assert.Nil(t, slices.Transform(in, func(i int) string { return "" }))
	})

	t.Run("int to string", func(t *testing.T) {
		t.Parallel()

		in := []int{1, 2, 3}
		out := slices.Transform(in, strconv.Itoa)
		assert.Equal(t, []string{"1", "2", "3"}, out)
	})
}
