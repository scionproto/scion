//  Copyright 2020 Smallstep Labs, Inc.
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

// This file is a copy of
// https://github.com/smallstep/cli/blob/111bcb9cfbb101718f9c4a39f5ab439504b9c07f/internal/cryptoutil/cryptoutil.go
// with the irrelevant parts stripped out and small adjustments to make it fit
// our codebase.

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"

	scionpki "github.com/scionproto/scion/scion-pki"
)

// IsX509Signer returns true if the given signer is supported by Go's
// crypto/x509 package to sign X509 certificates. This methods returns true
// for ECDSA, RSA and Ed25519 keys.
func IsX509Signer(signer crypto.Signer) bool {
	if signer == nil {
		return false
	}
	pub := signer.Public()
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return true
	default:
		return false
	}
}

type kmsSigner struct {
	crypto.PublicKey
	name     string
	kms, key string
}

// exitError returns the error displayed on stderr after running the given
// command.
func exitError(cmd *exec.Cmd, err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("command %q failed with:\n%s", cmd.String(), ee.Stderr)
	}
	return fmt.Errorf("command %q failed with: %w", cmd.String(), err)
}

// newKMSSigner creates a signer using `step-kms-plugin` as the signer.
func newKMSSigner(kms, key string) (*kmsSigner, error) {
	name, err := scionpki.LookKms()
	if err != nil {
		return nil, err
	}

	args := []string{"key"}
	if kms != "" {
		args = append(args, "--kms", kms)
	}
	args = append(args, key)

	// Get public key
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}

	pub, err := loadPublicKeyPem(out)
	if err != nil {
		return nil, err
	}

	return &kmsSigner{
		PublicKey: pub,
		name:      name,
		kms:       kms,
		key:       key,
	}, nil
}

// Public implements crypto.Signer and returns the public key.
func (s *kmsSigner) Public() crypto.PublicKey {
	return s.PublicKey
}

// Sign implements crypto.Signer using the `step-kms-plugin`.
func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	args := []string{"sign", "--format", "base64"}
	if s.kms != "" {
		args = append(args, "--kms", s.kms)
	}
	if _, ok := s.PublicKey.(*rsa.PublicKey); ok {
		if _, pss := opts.(*rsa.PSSOptions); pss {
			args = append(args, "--pss")
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			args = append(args, "--alg", "SHA256")
		case crypto.SHA384:
			args = append(args, "--alg", "SHA384")
		case crypto.SHA512:
			args = append(args, "--alg", "SHA512")
		default:
			return nil, fmt.Errorf("unsupported hash function %q", opts.HashFunc().String())
		}
	}
	args = append(args, s.key)

	//nolint:gosec // arguments controlled by step.
	cmd := exec.Command(s.name, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(digest)
	}()
	out, err := cmd.Output()
	if err != nil {
		return nil, exitError(cmd, err)
	}
	return base64.StdEncoding.DecodeString(string(out))
}
