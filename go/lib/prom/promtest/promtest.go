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

// Package promtest contains helpers to test metrics structs.
package promtest

import (
	"reflect"
	"testing"

	"github.com/iancoleman/strcase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CheckLabelsStruct checks that labels has a Values and Labels method. It also
// checks that Labels returns the struct field names.
func CheckLabelsStruct(t *testing.T, labels interface{}) {
	labelsType := reflect.TypeOf(labels)
	labelsInst := reflect.New(labelsType)
	labelsMethod := labelsInst.MethodByName("Labels")
	require.NotNil(t, labelsMethod, "Labels method missing")
	valuesMethod := labelsInst.MethodByName("Values")
	require.NotNil(t, valuesMethod, "Values method missing")

	var fieldNames []string
	for i := 0; i < labelsType.NumField(); i++ {
		fieldNames = append(fieldNames, strcase.ToSnake(labelsType.Field(i).Name))
	}
	callResult := labelsMethod.Call([]reflect.Value{})
	require.Equal(t, 1, len(callResult), "Values result length wrong")
	actLabels, ok := callResult[0].Interface().([]string)
	require.True(t, ok, "Values returns wrong type")
	assert.ElementsMatch(t, fieldNames, actLabels, "Expected %v but was %v", fieldNames, actLabels)
}
