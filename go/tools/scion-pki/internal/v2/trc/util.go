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

package trc

import (
	"fmt"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

// Dir returns the directory where TRCs are written to.
func Dir(isd addr.ISD) string {
	return filepath.Join(pkicmn.GetIsdPath(pkicmn.OutDir, isd), pkicmn.TRCsDir)
}

// PartsDir returns the directory where the partially signed TRC is written to.
func PartsDir(isd addr.ISD, ver uint64) string {
	return filepath.Join(Dir(isd), fmt.Sprintf(pkicmn.TRCPartsDirFmt, isd, ver))
}

// ProtoFile returns the file path for the prototype TRC.
func ProtoFile(isd addr.ISD, ver uint64) string {
	return filepath.Join(PartsDir(isd, ver), fmt.Sprintf(pkicmn.TRCProtoNameFmt, isd, ver))
}
