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

package pktcls

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func failOnErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func mustMarshalToFile(t *testing.T, v interface{}, baseName string) {
	enc, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(enc)
	if err := buffer.WriteByte('\n'); err != nil {
		t.Fatal(err)
	}

	if err := ioutil.WriteFile(expandPath(baseName), buffer.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
}

func expandPath(file string) string {
	return filepath.Join("testdata", fmt.Sprintf("%s.ref", file))
}
