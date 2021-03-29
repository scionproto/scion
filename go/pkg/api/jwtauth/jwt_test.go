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

package jwtauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/pkg/api/jwtauth"
)

var serverKey = []byte{
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
}

var shortKey = []byte{
	0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
}

var badKey = []byte{
	9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
	9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
}

// startServer launches a server with authorization checks on the loopback
// address. The port is chosen dynamically to ensure that it doesn't clash with
// existing servers on the local system.
//
// It returns the server object (so it can be closed by the caller) and an
// URL that can be accessed for testing.
func startServer(t *testing.T) (*http.Server, string) {
	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	verifier := jwtauth.HTTPVerifier{Key: serverKey}
	authorizedHandler := verifier.AddAuthorization(handler)

	srv := http.Server{
		Handler: authorizedHandler,
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
	require.NoError(t, err)

	go func() {
		if err := srv.Serve(listener); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP Server ListenAndServe: %v", err)
			}
		}
	}()

	url := fmt.Sprintf("http://%v", listener.Addr().String())
	return &srv, url
}

func TestNewHTTPClient(t *testing.T) {
	testCases := map[string]struct {
		TokenSource        jwtauth.TokenSource
		ExpectedError      require.ErrorAssertionFunc
		ExpectedHTTPStatus int
	}{
		"rejected key client": {
			TokenSource: &jwtauth.JWTTokenSource{Subject: "example", Key: shortKey},
			// Key is rejected by client-side code, so the request doesn't even reach the
			// server.
			ExpectedError: require.Error,
		},
		"unauthorized client": {
			TokenSource:        nil,
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusInternalServerError,
		},
		"bad key client": {
			TokenSource:        &jwtauth.JWTTokenSource{Subject: "example", Key: badKey},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusInternalServerError,
		},
		"authorized client": {
			TokenSource:        &jwtauth.JWTTokenSource{Subject: "example", Key: serverKey},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
		"authorized client without Subject": {
			TokenSource:        &jwtauth.JWTTokenSource{Key: serverKey},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
	}

	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, url := startServer(t)
			defer srv.Close()

			client := jwtauth.NewHTTPClient(context.Background(), tc.TokenSource)
			response, err := client.Get(url)

			tc.ExpectedError(t, err)
			if err == nil {
				assert.Equal(t, response.StatusCode, tc.ExpectedHTTPStatus)
			}
		})
	}
}
