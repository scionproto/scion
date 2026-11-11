// Copyright 2026 ETH Zurich
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

package token

import "context"

type Provider interface {
	// Token should always return a not expired token or an error otherwise.
	Token(context.Context) (string, error)
	// Renew can be called to manually request a token renewal independent of the token expiration.
	Renew(context.Context) error
	Close() error
}

type StaticTokenProvider struct {
	token string
}

func NewStaticTokenProvider(token string) *StaticTokenProvider {
	return &StaticTokenProvider{
		token: token,
	}
}

func (s *StaticTokenProvider) Token(_ context.Context) (string, error) {
	return s.token, nil
}

func (s *StaticTokenProvider) Renew(_ context.Context) error {
	return nil
}

func (s *StaticTokenProvider) Close() error {
	return nil
}
