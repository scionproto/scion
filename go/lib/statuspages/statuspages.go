// Copyright 20202 Anapaya Systems
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

package statuspages

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"

	toml "github.com/pelletier/go-toml"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/util"
)

const mainTmpl = `
<!DOCTYPE html>
<html>
	<head>
		<title>{{ .ElemId }}</title>
	</head>
	<body style="font-family:sans-serif">
		<h1>{{ .ElemId }}</h1>
		{{ range .Pages }}
		<p><a href="{{ . }}">[{{ . }}]</a></p>
		{{ end }}
	</body>
</html>
`

type mainData struct {
	ElemId string
	Pages  []string
}

var (
	elemId string
	pages  []string
	cfg    interface{}
)

// Init adds common status pages to the default web server.
func Init(elementId string, config interface{}) {
	elemId = elementId
	cfg = config
	// Main page doesn't have to be linked from itself.
	http.HandleFunc("/", mainHandler)
	// Following pages will be listed on the main page.
	Add("info", infoHandler)
	if cfg != nil {
		Add("config", configHandler)
	}
	// This page is already served by the Prometheus client.
	// Link it from the main page.
	pages = append(pages, "metrics")
}

// Add adds a custom status page to the default web server.
// The status page will be also linked from the main page.
func Add(page string, handler http.HandlerFunc) {
	pages = append(pages, page)
	http.HandleFunc("/"+page, handler)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("main").Parse(mainTmpl)
	if err != nil {
		http.Error(w, "Cannot parse template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, mainData{ElemId: elemId, Pages: pages})
}

func infoHandler(w http.ResponseWriter, r *http.Request) {
	info := env.VersionInfo()
	inDocker, err := util.RunsInDocker()
	if err == nil {
		info += fmt.Sprintf("  In docker:     %v\n", inDocker)
	}
	info += fmt.Sprintf("  pid:           %d\n", os.Getpid())
	info += fmt.Sprintf("  euid/egid:     %d %d\n", os.Geteuid(), os.Getegid())
	info += fmt.Sprintf("  cmd line:      %q\n", os.Args)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, info)
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	var buf bytes.Buffer
	toml.NewEncoder(&buf).Order(toml.OrderPreserve).Encode(cfg)
	fmt.Fprint(w, buf.String())
}
