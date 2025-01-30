// Copyright 2020 Anapaya Systems
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

// Package feature provides a simple mechanism for command line tools to
// take and parse feature flags.
//
// Feature flag sets are passed as a struct of booleans. Non-boolean fields
// are ignored during parsing.
package feature

import (
	"reflect"
	"sort"
	"strings"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// Parse parses the features from the input into the feature set. The provided
// feature set should be a pointer to a struct. All boolean fields on that
// struct are discovered as feature flags. Non-boolean fields are ignored.
func Parse(input []string, featureSet any) error {
	val := reflect.ValueOf(featureSet)
	if !val.IsValid() || val.IsZero() {
		return serrors.New("feature set must not be nil")
	} else if val.Kind() != reflect.Ptr {
		return serrors.New("feature set must be pointer")
	}

	m := featureMap(featureSet)
	for _, key := range input {
		index, ok := m[key]
		if !ok {
			return serrors.New("feature not supported", "feature", key)
		}
		val.Elem().Field(index).SetBool(true)
	}
	return nil
}

// ParseDefault parses the default features from input.
func ParseDefault(input []string) (Default, error) {
	var d Default
	if err := Parse(input, &d); err != nil {
		return Default{}, err
	}
	return d, nil
}

// Features lists the supported features.
func Features(featureSet any) []string {
	m := featureMap(featureSet)
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// String returns the features as a sorted list separated by the provided separator.
func String(featureSet any, sep string) string {
	return strings.Join(Features(featureSet), sep)
}

func featureMap(featureSet any) map[string]int {
	m := map[string]int{}
	val := reflect.ValueOf(featureSet)
	if !val.IsValid() {
		return nil
	}
	fields := val.Type()
	if fields.Kind() == reflect.Ptr {
		fields = fields.Elem()
	}
	for i := 0; i < fields.NumField(); i++ {
		if fields.Field(i).Type.Kind() != reflect.Bool {
			continue
		}
		name := fields.Field(i).Name
		// if there is a feature tag use that:
		if v, ok := fields.Field(i).Tag.Lookup("feature"); ok {
			name = strings.Split(v, ",")[0]
		}
		m[name] = i
	}
	return m
}

// Default describes the default feature set.
type Default struct {
	HeaderLegacy bool `feature:"header_legacy"`
}
