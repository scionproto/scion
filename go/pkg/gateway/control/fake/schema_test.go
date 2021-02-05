// Copyright 2021 Anapaya Systems
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

package fake_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"
)

func TestExampleValidates(t *testing.T) {
	schemaLoader := gojsonschema.NewReferenceLoader("file://./configuration.schema.json")
	documentLoader := gojsonschema.NewReferenceLoader("file://./example_configuration.gatewaytest")
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	require.NoError(t, err)
	assert.True(t, result.Valid())
	for _, err := range result.Errors() {
		t.Log(err)
	}
}
