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

package mgmtapi

import (
	"bytes"
	"embed"
	"net/http"
	"time"

	"github.com/scionproto/scion/private/mgmtapi"
)

//go:embed *.html
var f embed.FS

var (
	index = mgmtapi.ResolveIndex(f)

	modtime = time.Now()

	spec = func() []byte {
		raw, err := rawSpec()
		if err != nil {
			panic(err)
		}
		return raw
	}()
)

// ServeSpecInteractive serves the interactive redocly OpenAPI3 spec.
func ServeSpecInteractive(w http.ResponseWriter, r *http.Request) {
	http.ServeContent(w, r, "index.html", modtime, bytes.NewReader(index))
}

// ServeSpecJSON serves the json encoded OpenAPI3 spec.
func ServeSpecJSON(w http.ResponseWriter, r *http.Request) {
	http.ServeContent(w, r, "openapi.json", modtime, bytes.NewReader(spec))
}
