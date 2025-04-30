// Copyright 2025 SCION Association
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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/mgmtapi/jwtauth"
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

func keyFunc(key []byte, err error) func() ([]byte, error) {
	// Use a custom function instead of gomock because it is simple to do via a
	// function and it avoids the creation of an interface type in the API of
	// the package and the mock creation boilerplate.
	return func() ([]byte, error) {
		return key, err
	}
}

// startServer launches a server with authorization checks on the loopback
// address. The port is chosen dynamically to ensure that it doesn't clash with
// existing servers on the local system.
//
// It returns the server object (so it can be closed by the caller) and an
// URL that can be accessed for testing.
func startServer(t *testing.T, nowFn func() time.Time) (url string) {
	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	verifier := jwtauth.HTTPVerifier{Generator: keyFunc(serverKey, nil)}
	authorizedHandler := verifier.AddAuthorization(handler, nowFn)

	srv := http.Server{
		Handler: authorizedHandler,
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP{127, 0, 0, 1}})
	require.NoError(t, err)

	t.Cleanup(func() { srv.Close() })

	go func() {
		if err := srv.Serve(listener); err != nil {
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP Server ListenAndServe: %v", err)
			}
		}
	}()

	return fmt.Sprintf("http://%v", listener.Addr().String())
}

func TestNewHTTPClient(t *testing.T) {
	now := time.Date(2025, 5, 1, 10, 20, 30, 0, time.UTC)

	testCases := map[string]struct {
		run                bool
		TokenSource        jwtauth.TokenSource
		ExpectedError      require.ErrorAssertionFunc
		ExpectedHTTPStatus int
	}{
		"nil generator": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject: "example",
			},
			ExpectedError: require.Error,
		},
		"error generator": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				Generator: keyFunc(serverKey, serrors.New("test error")),
			},
			ExpectedError: require.Error,
		},
		"rejected key client": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				Generator: keyFunc(shortKey, nil),
			},
			// Key is rejected by client-side code, so the request doesn't even reach the
			// server.
			ExpectedError: require.Error,
		},
		"unauthorized client": {
			TokenSource:        nil,
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusUnauthorized,
		},
		"bad key client": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				Generator: keyFunc(badKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusUnauthorized,
		},
		"authorized client": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				Generator: keyFunc(serverKey, nil),
				// 1 Minute before expiry.
				IssuedAt: now.Add(-1*jwtauth.DefaultTokenLifetime + time.Second),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
		"issued in the future": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				IssuedAt:  now.Add(time.Minute), // 1 minute ahead of current time.
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusUnauthorized,
		},
		"issued in the future within skew": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				IssuedAt:  now.Add(time.Second), // 1 second ahead of current time.
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
		"issued in the past with default lifetime but expired": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject: "example",
				// Expired by 1 minute.
				IssuedAt:  now.Add(-1 * (jwtauth.DefaultTokenLifetime + time.Minute)),
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusUnauthorized,
		},
		"issued in the past with custom lifetime but expired": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				IssuedAt:  now.Add(-6 * time.Minute), // 6 minutes ago.
				Lifetime:  5 * time.Minute,           // Expired by 1 minute.
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusUnauthorized,
		},
		"issued in the past with custom lifetime and valid": {
			TokenSource: &jwtauth.JWTTokenSource{
				Subject:   "example",
				IssuedAt:  now.Add(-6 * time.Minute), // 6 minutes ago.
				Lifetime:  10 * time.Minute,
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
		"authorized client without Subject": {
			TokenSource: &jwtauth.JWTTokenSource{
				IssuedAt:  now.Add(-1 * time.Minute), // 1 minute ago.
				Generator: keyFunc(serverKey, nil),
			},
			ExpectedError:      require.NoError,
			ExpectedHTTPStatus: http.StatusOK,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			url := startServer(t, func() time.Time { return now })

			client := jwtauth.NewHTTPClient(tc.TokenSource)
			response, err := client.Get(url)

			tc.ExpectedError(t, err)
			if err == nil {
				assert.Equal(t, tc.ExpectedHTTPStatus, response.StatusCode)
			}
		})
	}
}
