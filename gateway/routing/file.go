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

// File file.go contains methods to interact with policies on the disk.

package routing

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// LoadPolicy loads the policy file from the path.
func LoadPolicy(path string) (Policy, error) {
	p := Policy{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, serrors.Wrap("reading file", err)
	}
	if err := p.UnmarshalText(raw); err != nil {
		return Policy{}, serrors.Wrap("parsing file", err, "file", path)
	}
	return p, nil
}

// PolicyPublisher is used to publish policies.
type PolicyPublisher interface {
	PublishRoutingPolicy(*Policy)
	RoutingPolicy() *Policy
}

// NewPolicyHandler creates a HTTP handler for the reloadable policy. If the
// path is not empty, a PUT request will write a valid received policy to this
// path.
func NewPolicyHandler(policyPublisher PolicyPublisher,
	path string) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/plain")
			p := policyPublisher.RoutingPolicy()
			if p == nil {
				return
			}
			raw, err := p.MarshalText()
			if err != nil {
				http.Error(w, fmt.Sprintf("Error writing: %v", err),
					http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(raw)
		case http.MethodPut:
			rawPolicy, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			p := Policy{}
			if err := p.UnmarshalText(rawPolicy); err != nil {
				http.Error(w, fmt.Sprintf("Error parsing: %v", err), http.StatusBadRequest)
				return
			}
			if path != "" {
				if err := os.WriteFile(path, rawPolicy, 0666); err != nil {
					http.Error(w, fmt.Sprintf("Error writing file: %v", err),
						http.StatusInternalServerError)
					return
				}
			}
			policyPublisher.PublishRoutingPolicy(&p)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}
