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

package as_conf

import (
	"encoding/base64"
	"io/ioutil"

	"path/filepath"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	MasterKey0 = "master0.key"
	MasterKey1 = "master1.key"
)

type MasterKeys struct {
	Key0 common.RawBytes
	Key1 common.RawBytes
}

func LoadMasterKeys(keyDir string) (*MasterKeys, error) {
	var err error
	keys := &MasterKeys{}
	if keys.Key0, err = loadMasterKey(filepath.Join(keyDir, MasterKey0)); err != nil {
		return nil, err
	}
	if keys.Key1, err = loadMasterKey(filepath.Join(keyDir, MasterKey1)); err != nil {
		return nil, err
	}
	return keys, nil
}

// loadMasterKey decodes a base64 encoded master key in file and returns the raw bytes.
func loadMasterKey(file string) (common.RawBytes, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, common.NewBasicError(ErrorOpen, err)
	}
	dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dbuf, b)
	if err != nil {
		return nil, common.NewBasicError(ErrorParse, err)
	}
	return dbuf[:n], nil
}
