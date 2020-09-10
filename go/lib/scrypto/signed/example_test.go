// Copyright 2020 Anapaya Systems
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

package signed_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/scionproto/scion/go/lib/scrypto/signed"
	cryptopb "github.com/scionproto/scion/go/pkg/proto/crypto"
)

func ExampleSign_basic() {
	// Choose private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Define message to sign.
	hdr := signed.Header{
		SignatureAlgorithm: signed.ECDSAWithSHA512,
		Timestamp:          time.Now(),
	}
	body := []byte("very important message")

	// Sign the message.
	signedMsg, err := signed.Sign(hdr, body, privateKey)
	if err != nil {
		panic(err)
	}

	// Extract body without verification. Usually, you will not need this operation.
	unverifiedBody, err := signed.ExtractUnverifiedBody(signedMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(unverifiedBody))
	// Output:
	// very important message
}

func ExampleSign_withAssociatedData() {
	// Choose private key.
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Define message to sign.
	hdr := signed.Header{
		SignatureAlgorithm:   signed.ECDSAWithSHA512,
		AssociatedDataLength: 8,
	}
	body := []byte("very important message")
	associatedData := [][]byte{[]byte("more"), []byte("data")}

	// Sign the message.
	signedMsg, err := signed.Sign(hdr, body, privateKey, associatedData...)
	if err != nil {
		panic(err)
	}

	// Extract body without verification. Usually, you will not need this operation.
	unverifiedBody, err := signed.ExtractUnverifiedBody(signedMsg)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(unverifiedBody))
	// Output:
	// very important message
}

func ExampleVerify_basic() {
	signedMsg, publicKey := basicSignedMessage()

	verifiedMsg, err := signed.Verify(signedMsg, publicKey)
	if err != nil {
		panic(err)
	}
	meta := verifiedMsg.Header.Metadata
	keyID := verifiedMsg.Header.VerificationKeyID
	body := verifiedMsg.Body

	fmt.Printf("meta: %q keyID: %q body: %q", meta, keyID, body)
	// Output:
	// meta: "metadata" keyID: "keyID" body: "very important message"
}

func ExampleVerify_withAssociatedData() {
	signedMsg, publicKey := signedMessageWithAssociatedData()

	_, err := signed.Verify(signedMsg, publicKey)
	if err == nil {
		panic("associated data is required")
	}

	verifiedMsg, err := signed.Verify(signedMsg, publicKey, []byte("out-of-band"))
	if err != nil {
		panic(err)
	}
	meta := verifiedMsg.Header.Metadata
	keyID := verifiedMsg.Header.VerificationKeyID
	body := verifiedMsg.Body

	fmt.Printf("meta: %q keyID: %q body: %q", meta, keyID, body)
	// Output:
	// meta: "metadata" keyID: "keyID" body: "very important message"
}

func basicSignedMessage() (*cryptopb.SignedMessage, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	hdr := signed.Header{
		SignatureAlgorithm: signed.ECDSAWithSHA512,
		Metadata:           []byte("metadata"),
		VerificationKeyID:  []byte("keyID"),
	}
	body := []byte("very important message")
	signedMsg, err := signed.Sign(hdr, body, privateKey)
	if err != nil {
		panic(err)
	}
	return signedMsg, privateKey.Public()
}

func signedMessageWithAssociatedData() (*cryptopb.SignedMessage, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	hdr := signed.Header{
		SignatureAlgorithm:   signed.ECDSAWithSHA512,
		Metadata:             []byte("metadata"),
		VerificationKeyID:    []byte("keyID"),
		AssociatedDataLength: 11,
	}
	body := []byte("very important message")
	associatedData := []byte("out-of-band")
	signedMsg, err := signed.Sign(hdr, body, privateKey, associatedData)
	if err != nil {
		panic(err)
	}
	return signedMsg, privateKey.Public()
}
