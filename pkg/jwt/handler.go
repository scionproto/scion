// Copyright 2026 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/scionproto/scion/pkg/private/serrors"
)

type Signer struct {
	privKey ed25519.PrivateKey
}

func SignerFromFile(privateKeyFile string) (*Signer, error) {
	privData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privData)
	if block == nil {
		return nil, serrors.New("failed to decode PEM")
	}

	privkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := privkey.(ed25519.PrivateKey)
	if !ok {
		return nil, serrors.New("not an Ed25519 private key")
	}
	return NewSigner(priv), nil
}

func NewSigner(privKey ed25519.PrivateKey) *Signer {
	return &Signer{
		privKey: privKey,
	}
}

func (s *Signer) GenerateToken(claims map[string]any) (string, error) {
	builder := jwt.NewBuilder()

	for k, v := range claims {
		builder = builder.Claim(k, v)
	}

	token, err := builder.Build()
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), s.privKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

type Verifier struct {
	pubKey ed25519.PublicKey
}

func VerifierFromFile(publicKeyFile string) (*Verifier, error) {
	pubData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 public key")
	}
	return NewVerifier(pub), nil
}

func NewVerifier(pubKey ed25519.PublicKey) *Verifier {
	return &Verifier{
		pubKey: pubKey,
	}
}

func (v *Verifier) VerifyToken(tokenStr string) (jwt.Token, error) {
	tok, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKey(jwa.EdDSA(), v.pubKey),
	)
	if err != nil {
		fmt.Println(tokenStr, err)
		return nil, err
	}

	return tok, nil
}
