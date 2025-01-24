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

	"github.com/scionproto/scion/pkg/private/prom"
)

// CheckLabelsStruct checks that labels has a Values and Labels method. It also
// checks that labels.Labels() returns the struct field names.
func CheckLabelsStruct(t *testing.T, xLabels any) {
	v, ok := xLabels.(prom.Labels)
	if !ok {
		assert.Fail(t, "should implement labels interface")
	}

	assert.Equal(t, len(v.Values()), len(v.Labels()), "should match in length")
	fields := fieldNames(v)
	assert.ElementsMatch(t, fields, v.Labels(), "Expected %v but was %v", fields, v.Labels())
}

func fieldNames(xLabels prom.Labels) []string {
	names := []string{}
	labelsType := reflect.TypeOf(xLabels)
	for i := 0; i < labelsType.NumField(); i++ {
		field := labelsType.Field(i)
		// handle nesting of other labels structs:
		if field.Type.Implements(reflect.TypeOf((*prom.Labels)(nil)).Elem()) {
			names = append(names, fieldNames(reflect.Zero(field.Type).Interface().(prom.Labels))...)
		} else {
			names = append(names, strcase.ToSnake(field.Name))
		}
	}
	return names
}
