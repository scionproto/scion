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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/pkg/ca/api"
)

const (
	// DefaultTokenLifetime is the default duration tokens are valid for.
	DefaultTokenLifetime = 10 * time.Minute
	// DefaultAcceptableSkew is the clock skew allowed between token creation and token validation
	// machines. Tokens are not valid before (iat - clock_skew) and after (exp + clock_skew).
	DefaultAcceptableSkew = 5 * time.Second
)

// NewHTTPClient constructs a new HTTP client that attempts to perform authorization
// via Bearer tokens created by src.
//
// If src is nil then a default HTTP client is returned (i.e., one that
// does not perform any authorization).
//
// For a simple example of how to use this, see the test.
func NewHTTPClient(src TokenSource) *http.Client {
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
	// Subject is an informational field that will be used as the JWT "sub" and
	// "iss" claims. If empty, the "sub" and "iss" claims are not set.
	Subject string
	// Lifetime is the duration a token is valid for. If it is 0, then DefaultTokenLifetime is
	// used.
	Lifetime time.Duration
	// IssuedAt is the timestamp when the token should report that it was issued. Values are
	// rounded down to whole seconds. If not set, time.Now() is used instead.
	IssuedAt time.Time
	// Generator that creates symmetric keys for HS256. For security
	// reasons, the generated key must be at least 256-bit long (see
	// https://tools.ietf.org/html/rfc7518#section-3.2). If the key is not
	// sufficiently long, token creation will return an error.
	Generator KeyFunc
}

func (s *JWTTokenSource) Token() (*Token, error) {
	issuedAt := s.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}

	lifetime := s.Lifetime
	if lifetime == 0 {
		lifetime = DefaultTokenLifetime
	}

	if s.Generator == nil {
		return nil, serrors.New("key generator must not be nil")
	}
	key, err := s.Generator()
	if err != nil {
		return nil, serrors.WrapStr("generating key", err)
	}
	if len(key) < 256/8 {
		return nil, serrors.New("refusing to sign, key must be at least 256 bits long",
			"length", len(key)*8)
	}

	token := jwt.New()
	if s.Subject != "" {
		if err := token.Set(jwt.SubjectKey, s.Subject); err != nil {
			return nil, jwtSetError(jwt.SubjectKey, err)
		}
		if err := token.Set(jwt.IssuerKey, s.Subject); err != nil {
			return nil, jwtSetError(jwt.IssuerKey, err)
		}
	}

	if err := token.Set(jwt.IssuedAtKey, issuedAt.Unix()); err != nil {
		return nil, jwtSetError(jwt.IssuedAtKey, err)
	}
	if err := token.Set(jwt.ExpirationKey, issuedAt.Add(lifetime).Unix()); err != nil {
		return nil, jwtSetError(jwt.ExpirationKey, err)
	}

	b, err := jwt.Sign(token, jwa.HS256, key)
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
	// Generator that creates keys for HS256. For security reasons, the keys must be
	// at least 256-bit long (see https://tools.ietf.org/html/rfc7518#section-3.2). If the key is
	// not sufficiently long, token creation will return an error.
	Generator KeyFunc
	// Logger is an optional Logger to be used for listing successful/unsuccessful authorization
	// attempts. If nil, no logging is done.
	Logger log.Logger
}

// AddAuthorization decorates handler with a step that first performs JWT Bearer
// authorization before chaining the call to the initial handler.
func (v *HTTPVerifier) AddAuthorization(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if v.Generator == nil {
			log.SafeDebug(v.Logger, "Key generator must not be nil")
			e := &Error{Code: http.StatusInternalServerError, Title: "Server error"}
			e.Write(rw)
			return
		}
		key, err := v.Generator()
		if err != nil {
			log.SafeDebug(v.Logger, "Key generator returned error", "err", err)
			e := &Error{Code: http.StatusInternalServerError, Title: "Server error"}
			e.Write(rw)
			return
		}
		if len(key) < 256/8 {
			log.SafeDebug(v.Logger, "Refusing to verify, key must be at least 256 bits long",
				"length", len(key)*8)
			e := &Error{Code: http.StatusInternalServerError, Title: "Server error"}
			e.Write(rw)
			return
		}

		token, err := jwt.ParseRequest(req,
			jwt.WithVerify(jwa.HS256, key),
		)
		if err != nil {
			log.SafeDebug(v.Logger, "Token verification failed", "err", err)
			e := &Error{Code: http.StatusInternalServerError, Title: "Authorization error"}
			e.Write(rw)
			return
		}

		err = jwt.Validate(token,
			jwt.WithClock(jwt.ClockFunc(time.Now)),
			jwt.WithAcceptableSkew(DefaultAcceptableSkew),
		)
		if err != nil {
			log.SafeDebug(v.Logger, "Token validation failed", "err", err)
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

// KeyFunc is a generator for keys used in JWT token creation.
type KeyFunc func() ([]byte, error)

func jwtSetError(claim string, err error) error {
	s := fmt.Sprintf("setting %v claim", claim)
	return serrors.WrapStr(s, err)
}
