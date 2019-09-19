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
)

// CheckLabelsStruct checks that labels has a Values and Labels method. It also
// checks that labels.Labels() returns the struct field names.
func CheckLabelsStruct(t *testing.T, xLabels interface{}) {
	type label interface {
		Labels() []string
		Values() []string
	}

	v, ok := xLabels.(label)
	if ok != true {
		assert.Fail(t, "should implement label interface")
	}

	assert.Equal(t, len(v.Values()), len(v.Labels()), "should match in length")

	fieldNames := []string{}
	labelsType := reflect.TypeOf(xLabels)
	for i := 0; i < labelsType.NumField(); i++ {
		fieldNames = append(fieldNames, strcase.ToSnake(labelsType.Field(i).Name))
	}
	assert.ElementsMatch(t, fieldNames, v.Labels(), "Expected %v but was %v",
		fieldNames, v.Labels())
}
