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

package service

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
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

// StatusPages describes a status page (HTTP endpoint exposed by the service).
type StatusPage struct {
	// Handler processes the HTTP request for this status page.
	Handler http.HandlerFunc
	// Special status page is one that should not be dumped via /all endpoint.
	// This can be because it uses PUT instead of GET, because it requires extra
	// query parameters, because it has side effects or simply because it is too
	// expensive to evaluate.
	Special bool
}

// StatusPages maps the page URL to the page description.
type StatusPages map[string]StatusPage

// Register registers the pages with the supplied HTTP server.
// Additionally it registers the main page that links to all the other pages.
func (s StatusPages) Register(serveMux *http.ServeMux, elemId string) error {
	t, err := template.New("main").Parse(mainTmpl)
	if err != nil {
		return err
	}
	var pages []string
	for endpoint, page := range s {
		pages = append(pages, endpoint)
		serveMux.HandleFunc(fmt.Sprintf("/%s", endpoint), page.Handler)
	}
	pages = append(pages, "metrics")
	sort.Strings(pages)
	var mainBuf bytes.Buffer
	if err := t.Execute(&mainBuf, mainData{ElemId: elemId, Pages: pages}); err != nil {
		return serrors.WrapStr("executing template", err)
	}
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, mainBuf.String())
	})
	serveMux.HandleFunc("/all", func(w http.ResponseWriter, r *http.Request) {
		var endpoints []string
		for endpoint := range s {
			endpoints = append(endpoints, endpoint)
		}
		sort.Strings(endpoints)
		for _, endpoint := range endpoints {
			if s[endpoint].Special {
				continue
			}
			fmt.Fprintf(w, "\n\n%s\n%s\n\n", endpoint, strings.Repeat("=", len(endpoint)))
			s[endpoint].Handler(w, r)
		}
		// There's a lot of metrics, put them at the end so that they don't obscure other stuff.
		fmt.Fprintf(w, "\n\nmetrics\n=======\n\n")
		promhttp.Handler().ServeHTTP(w, r)
	})
	return nil
}

// NewConfigStatusPage returns a page with the specified TOML config.
func NewConfigStatusPage(config interface{}) StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		var buf bytes.Buffer
		toml.NewEncoder(&buf).Order(toml.OrderPreserve).Encode(config)
		fmt.Fprint(w, buf.String())
	}
	return StatusPage{Handler: handler}
}

// NewInfoStatusPage returns a page with basic info about the process.
func NewInfoStatusPage() StatusPage {
	handler := func(w http.ResponseWriter, r *http.Request) {
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
	return StatusPage{Handler: handler}
}

// NewLogLevelStatusPage returns a page with basic info about the process.
func NewLogLevelStatusPage() StatusPage {
	return StatusPage{Handler: log.ConsoleLevel.ServeHTTP}
}
