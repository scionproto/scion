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

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/proto/aa"
	"github.com/scionproto/scion/pkg/proto/aa/v1/aaconnect"
)

type AnapayaAuthProvider struct {
	apiKey     string
	client     aaconnect.AuthServiceClient
	token      atomic.Value
	expiration time.Time
	cancelF    context.CancelFunc
}

func NewAnapayaAuthProvider(ctx context.Context, apiKey string) (*AnapayaAuthProvider, error) {
	provider := &AnapayaAuthProvider{
		apiKey: apiKey,
		client: aaconnect.NewAuthServiceClient(http.DefaultClient, "https://auth.scion.anapaya.net"),
	}
	err := provider.Renew(ctx)
	if err != nil {
		return nil, err
	}
	cancelCtx, cancelF := context.WithCancel(context.Background())
	provider.cancelF = cancelF
	provider.startFetcherRoutine(cancelCtx)
	return provider, nil
}

func (a *AnapayaAuthProvider) Token(ctx context.Context) (string, error) {
	return a.token.Load().(string), nil
}

func (a *AnapayaAuthProvider) Renew(ctx context.Context) error {
	newToken, err := a.fetchToken(ctx)
	if err != nil {
		return err
	}
	tok, err := jwt.ParseInsecure([]byte(newToken))
	if err != nil {
		return err
	}
	exp, ok := tok.Expiration()
	if !ok {
		return serrors.New("could not extract expiration from token")
	}
	a.token.Store(newToken)
	a.expiration = exp
	return nil
}

func (a *AnapayaAuthProvider) Close() error {
	if a.cancelF != nil {
		a.cancelF()
	}
	return nil
}

func (a *AnapayaAuthProvider) startFetcherRoutine(ctx context.Context) {
	go func() {
		defer log.HandlePanic()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(a.expiration) - time.Minute*10):
				ctx, cancelF := context.WithTimeout(ctx, time.Second*10)
				err := a.Renew(ctx)
				if err != nil {
					log.Debug("error renewing token", "err", err)
					time.Sleep(time.Second * 10)
				}
				cancelF()
			}
		}
	}()
}

func (a *AnapayaAuthProvider) fetchToken(ctx context.Context) (string, error) {
	keyResp, err := a.client.AuthenticateByKey(ctx, &connect.Request[aa.AuthenticateByKeyRequest]{
		Msg: &aa.AuthenticateByKeyRequest{
			ApiKey:            a.apiKey,
			RequestedValidity: 3600,
		},
	})
	if err != nil {
		return "", err
	}
	return keyResp.Msg.SnapToken, nil
}
