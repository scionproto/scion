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

// Package jwtauth includes helper functions for creating HTTP clients and servers
// that can perform JWT authorization via Bearer tokens.
package jwtauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/ca/api"
)

// NewHTTPClient constructs a new HTTP client that attempts to perform authorization
// via Bearer tokens created by src.
//
// If src is nil then a default HTTP client is returned (i.e., one that
// does not perform any authorization).
//
// For a simple example of how to use this, see the test.
func NewHTTPClient(ctx context.Context, src TokenSource) *http.Client {
	if src == nil {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &httpTransport{
			Base:        http.DefaultTransport,
			TokenSource: src,
		},
	}
}

// A TokenSource creates Bearer tokens for HTTP clients to use.
type TokenSource interface {
	Token() (*Token, error)
}

// Token is an HTTP Bearer token used by the SCION control-plane.
//
// The String method returns the representation of the token as it should be used
// in HTTP headers.
type Token struct {
	// value contains the token formatted ready for use in HTTP headers.
	value string
}

func (t *Token) String() string {
	if t == nil {
		return "<nil>"
	}
	return t.value
}

type httpTransport struct {
	Base        http.RoundTripper
	TokenSource TokenSource
}

func (t *httpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.TokenSource.Token()
	if err != nil {
		return nil, serrors.WrapStr("computing bearer token", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.String())
	return t.Base.RoundTrip(req)
}

// JWTTokenSource creates JWT tokens as defined by the SCION CA JWT specification.
//
// The signature algorithm is set to HS256.
type JWTTokenSource struct {
	// Subject is an informational field that will be used as the JWT "sub" claim. If empty,
	// the "sub" claim is not set.
	Subject string
	// Key used for HS256. For security reasons, the key must be
	// at least 256-bit long (see https://tools.ietf.org/html/rfc7518#section-3.2). If the key is
	// not sufficiently long, token creation will return an error.
	Key []byte
}

func (s *JWTTokenSource) Token() (*Token, error) {
	if len(s.Key) < 256/8 {
		return nil, serrors.New("refusing to sign, key must be at least 256 bits long",
			"length", len(s.Key)*8)
	}

	token := jwt.New()
	if s.Subject != "" {
		if err := token.Set("sub", s.Subject); err != nil {
			return nil, serrors.WrapStr("setting subject claim", err)
		}
	}

	b, err := jwt.Sign(token, jwa.HS256, s.Key)
	if err != nil {
		return nil, serrors.WrapStr("signing token", err)
	}

	return &Token{
		value: string(b),
	}, nil
}

// HTTPVerifier verifies a JWT token as defined by the SCION CA JWT specification.
//
// The only accepted algorithm is HS256.
type HTTPVerifier struct {
	// Key used for HS256. For security reasons, the key must be
	// at least 256-bit long (see https://tools.ietf.org/html/rfc7518#section-3.2). If the key is
	// not sufficiently long, token creation will return an error.
	Key []byte
	// Logger is an optional Logger to be used for listing successful/unsuccessful authorization
	// attempts. If nil, no logging is done.
	Logger log.Logger
}

// AddAuthorization decorates handler with a step that first performs JWT Bearer
// authorization before chaining the call to the initial handler.
func (v *HTTPVerifier) AddAuthorization(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if len(v.Key) < 256/8 {
			log.SafeDebug(v.Logger, "Refusing to verify, key must be at least 256 bits long",
				"length", len(v.Key)*8)
			e := &Error{Code: http.StatusInternalServerError, Title: "Server error"}
			e.Write(rw)
			return
		}

		token, err := jwt.ParseRequest(req, jwt.WithVerify(jwa.HS256, v.Key))
		if err != nil {
			log.SafeDebug(v.Logger, "Parsing failed", "err", err)
			e := &Error{Code: http.StatusInternalServerError, Title: "Authorization error"}
			e.Write(rw)
			return
		}

		log.SafeDebug(v.Logger, "Authorization successful", "subject", token.Subject())
		handler.ServeHTTP(rw, req)
	})
}

// Error models an error that can be sent in the respresentation of an OpenAPI
// JSON error, as defined in the CA OpenAPI Specification.
type Error struct {
	// Code is the HTTP code to send back to the client.
	Code int
	// Title is a short description of the error.
	Title string
}

func (e *Error) Write(rw http.ResponseWriter) {
	oa := &api.Problem{
		Status: e.Code,
		Title:  e.Title,
	}
	b, err := json.Marshal(oa)
	if err != nil {
		// We are unable to serialize an OpenAPI response. Fall back to
		// raw HTTP.
		http.Error(rw, "OpenAPI serialization error", http.StatusInternalServerError)
		return
	}

	http.Error(rw, string(b), e.Code)
}
