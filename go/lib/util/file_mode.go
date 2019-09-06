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

package util

import (
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

var _ (toml.TextUnmarshaler) = (*FileMode)(nil)

type FileMode os.FileMode

func (f *FileMode) UnmarshalText(text []byte) error {
	perm, err := strconv.ParseUint(string(text), 8, 32)
	*f = FileMode(perm)
	return err
}
