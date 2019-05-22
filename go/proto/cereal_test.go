// Copyright 2019 ETH Zurich
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

package proto

import (
	"errors"
	"strings"
	"testing"

	capnp "zombiezen.com/go/capnproto2"
)

func TestSafeExtract(t *testing.T) {
	pogsExtractF = panicExtract
	err := SafeExtract(nil, 0, capnp.Struct{})
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("error does not contain panic, err = %v", err)
	}

	pogsExtractF = errorExtract
	err = SafeExtract(nil, 0, capnp.Struct{})
	if err.Error() != "error" {
		t.Errorf("wrong error, have %v, expected %v", err, "error")
	}

	pogsExtractF = okExtract
	err = SafeExtract(nil, 0, capnp.Struct{})
	if err != nil {
		t.Errorf("bad return error, have %v, expected %v", err, nil)
	}
}

func panicExtract(_ interface{}, _ uint64, _ capnp.Struct) error {
	panic("bug")
}

func errorExtract(_ interface{}, _ uint64, _ capnp.Struct) error {
	return errors.New("error")
}

func okExtract(_ interface{}, _ uint64, _ capnp.Struct) error {
	return nil
}
