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

package trust_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"sync"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/pkg/storage/trust/sqlite"
	"github.com/scionproto/scion/go/pkg/trust"
)

func BenchmarkConcurrent10(b *testing.B) {
	db, err := sqlite.New("file::memory:")
	require.NoError(b, err)

	_, err = trust.LoadTRCs(context.Background(), "testdata/common/trcs", db)
	require.NoError(b, err)

	_, err = trust.LoadChains(context.Background(), "testdata/common/certs", db)
	require.NoError(b, err)

	signer := loadTrustSigner(b, db)

	associated := [][]byte{make([]byte, 300), make([]byte, 300), make([]byte, 300)}
	msg, err := signer.Sign(context.Background(), make([]byte, 5000), associated...)
	require.NoError(b, err)

	verifier := trust.Verifier{
		Engine: trust.Engine{
			Provider: trust.FetchingProvider{
				DB: db,
			},
			DB: db,
		},
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	for i := 0; i < b.N; i++ {
		wg.Add(10)
		for j := 0; j < 10; j++ {
			go func() {
				defer wg.Done()
				verifier.Verify(context.Background(), msg, associated...)
			}()
		}
		wg.Wait()
	}
}

func BenchmarkConcurrentCache10(b *testing.B) {
	db, err := sqlite.New("file::memory:")
	require.NoError(b, err)

	_, err = trust.LoadTRCs(context.Background(), "testdata/common/trcs", db)
	require.NoError(b, err)

	_, err = trust.LoadChains(context.Background(), "testdata/common/certs", db)
	require.NoError(b, err)

	signer := loadTrustSigner(b, db)

	associated := [][]byte{make([]byte, 300), make([]byte, 300), make([]byte, 300)}
	msg, err := signer.Sign(context.Background(), make([]byte, 5000), associated...)
	require.NoError(b, err)

	verifier := trust.Verifier{
		Engine: trust.Engine{
			Provider: trust.FetchingProvider{
				DB: db,
			},
			DB: db,
		},
		Cache: cache.New(time.Second, time.Minute),
	}

	b.ResetTimer()

	var wg sync.WaitGroup
	for i := 0; i < b.N; i++ {
		wg.Add(10)
		for j := 0; j < 10; j++ {
			go func() {
				defer wg.Done()
				verifier.Verify(context.Background(), msg, associated...)
			}()
		}
		wg.Wait()
	}
}

func loadTrustSigner(b *testing.B, db trust.DB) trust.Signer {
	raw, err := ioutil.ReadFile("testdata/common/ISD1/ASff00_0_110/crypto/as/cp-as.key")
	require.NoError(b, err)
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		panic("no valid private key block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(b, err)
	ret, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		panic("no valid ecdsa key")
	}
	chain, err := cppki.ReadPEMCerts("testdata/common/certs/ISD1-ASff00_0_110.pem")
	require.NoError(b, err)
	return trust.Signer{
		PrivateKey: ret,
		Algorithm:  signed.ECDSAWithSHA512,
		ChainValidity: cppki.Validity{
			NotBefore: chain[0].NotBefore,
			NotAfter:  chain[0].NotAfter,
		},
		Expiration:   chain[0].NotAfter,
		IA:           xtest.MustParseIA("1-ff00:0:110"),
		SubjectKeyID: chain[0].SubjectKeyId,
		TRCID: cppki.TRCID{
			ISD:    1,
			Base:   1,
			Serial: 1,
		},
	}
}
