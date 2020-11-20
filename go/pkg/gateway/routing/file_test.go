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

package routing_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/gateway/routing"
	"github.com/scionproto/scion/go/pkg/gateway/routing/mock_routing"
)

func TestLoadPolicy(t *testing.T) {
	dir, err := ioutil.TempDir("", "gateway-routing")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	writeTempFile := func(t *testing.T, raw []byte) string {
		f, err := ioutil.TempFile(dir, "gateway-routing")
		require.NoError(t, err)
		_, err = f.Write(raw)
		require.NoError(t, err)
		name := f.Name()
		f.Close()
		return name
	}

	type policyTest struct {
		Path           string
		ExpectedPolicy routing.Policy
		AssertErr      assert.ErrorAssertionFunc
	}
	testCases := map[string]func(*testing.T) policyTest{
		"path valid": func(t *testing.T) policyTest {
			p := routing.Policy{
				Rules: []routing.Rule{
					{
						Action:  routing.Accept,
						From:    routing.NewIAMatcher(t, "1-0"),
						To:      routing.NewIAMatcher(t, "0-0"),
						Network: routing.NewNetworkMatcher(t, "127.0.1.0/24"),
					},
				},
			}
			raw, err := p.MarshalText()
			require.NoError(t, err)
			file := writeTempFile(t, raw)
			return policyTest{
				Path:           file,
				ExpectedPolicy: p,
				AssertErr:      assert.NoError,
			}
		},
		"path non-existing": func(t *testing.T) policyTest {
			return policyTest{
				Path:      "non-existing",
				AssertErr: assert.Error,
			}
		},
		"path existing invalid": func(t *testing.T) policyTest {
			file := writeTempFile(t, []byte("garbage"))
			return policyTest{
				Path:      file,
				AssertErr: assert.Error,
			}
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			pt := tc(t)
			ap, err := routing.LoadPolicy(pt.Path)
			pt.AssertErr(t, err)
			assert.Equal(t, pt.ExpectedPolicy, ap)
		})
	}
}

func TestNewPolicyHandler(t *testing.T) {
	dir, err := ioutil.TempDir("", "gateway-routing")
	require.NoError(t, err)
	defer os.RemoveAll(dir)

	writeTempFile := func(t *testing.T, raw []byte) string {
		f, err := ioutil.TempFile(dir, "gateway-routing")
		require.NoError(t, err)
		_, err = f.Write(raw)
		require.NoError(t, err)
		name := f.Name()
		f.Close()
		return name
	}

	defaultPol := routing.Policy{
		Rules: []routing.Rule{
			{
				Action:  routing.Accept,
				From:    routing.NewIAMatcher(t, "1-0"),
				To:      routing.NewIAMatcher(t, "0-0"),
				Network: routing.NewNetworkMatcher(t, "127.0.1.0/24"),
			},
		},
	}
	updatePol := routing.Policy{
		Rules: []routing.Rule{
			{
				Action:  routing.Accept,
				From:    routing.NewIAMatcher(t, "0-0"),
				To:      routing.NewIAMatcher(t, "1-0"),
				Network: routing.NewNetworkMatcher(t, "127.0.1.0/24"),
			},
		},
	}

	type handlerTest struct {
		Path                string
		Request             *http.Request
		StatusCode          int
		ExpectedBody        []byte
		ExpectedFile        string
		ExpectedFileContent []byte
		Publisher           routing.PolicyPublisher
	}
	testCases := map[string]func(*testing.T, *gomock.Controller) handlerTest{
		"GET nil": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			require.NoError(t, err)
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			publisher.EXPECT().RoutingPolicy()
			return handlerTest{
				Request:      &http.Request{Method: http.MethodGet},
				StatusCode:   http.StatusOK,
				ExpectedBody: nil,
				Publisher:    publisher,
			}
		},
		"GET": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			raw, err := defaultPol.MarshalText()
			require.NoError(t, err)
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			publisher.EXPECT().RoutingPolicy().Return(&defaultPol)
			return handlerTest{
				Request:      &http.Request{Method: http.MethodGet},
				StatusCode:   http.StatusOK,
				ExpectedBody: raw,
				Publisher:    publisher,
			}
		},
		"PUT garbage": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			var body bytes.Buffer
			body.Write([]byte("garbage"))
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			return handlerTest{
				Request: &http.Request{
					Method: http.MethodPut,
					Body:   &readCloser{Buffer: body},
				},
				StatusCode: http.StatusBadRequest,
				Publisher:  publisher,
			}
		},
		"PUT valid no file": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			raw, err := updatePol.MarshalText()
			require.NoError(t, err)
			var body bytes.Buffer
			body.Write(raw)
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			publisher.EXPECT().PublishRoutingPolicy(&updatePol)
			return handlerTest{
				Request: &http.Request{
					Method: http.MethodPut,
					Body:   &readCloser{Buffer: body},
				},
				StatusCode: http.StatusOK,
				Publisher:  publisher,
			}
		},
		"PUT valid with file": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			rawCurrent, err := defaultPol.MarshalText()
			require.NoError(t, err)
			file := writeTempFile(t, rawCurrent)
			raw, err := updatePol.MarshalText()
			require.NoError(t, err)
			var body bytes.Buffer
			body.Write(raw)
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			publisher.EXPECT().PublishRoutingPolicy(&updatePol)
			return handlerTest{
				Path: file,
				Request: &http.Request{
					Method: http.MethodPut,
					Body:   &readCloser{Buffer: body},
				},
				StatusCode:          http.StatusOK,
				ExpectedFileContent: raw,
				ExpectedFile:        file,
				Publisher:           publisher,
			}
		},
		"PATCH": func(t *testing.T, ctrl *gomock.Controller) handlerTest {
			publisher := mock_routing.NewMockPolicyPublisher(ctrl)
			return handlerTest{
				Request:    &http.Request{Method: http.MethodPatch},
				StatusCode: http.StatusMethodNotAllowed,
				Publisher:  publisher,
			}
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			ht := tc(t, ctrl)
			handler := routing.NewPolicyHandler(ht.Publisher, ht.Path)
			w := httptest.NewRecorder()
			handler(w, ht.Request)
			assert.Equal(t, ht.StatusCode, w.Code)
			if ht.ExpectedBody != nil {
				assert.Equal(t, ht.ExpectedBody, w.Body.Bytes())
			}
			if ht.ExpectedFile != "" {
				fileContent, err := ioutil.ReadFile(ht.ExpectedFile)
				require.NoError(t, err)
				assert.Equal(t, ht.ExpectedFileContent, fileContent, "file content")
			}
		})
	}
}

type readCloser struct {
	bytes.Buffer
}

func (readCloser) Close() error { return nil }
