// Copyright 2026 SCION Association
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

package trcs_test

// TestMLDSACLIEndToEnd is an on-disk, CLI-function-driven end-to-end test that
// proves the scion-pki CLI command functions can produce and verify an
// ML-DSA-rooted trust chain.
//
// The test exercises the following CLI functions in sequence:
//
//  1. key.NewPrivateCmd — generates ML-DSA-65 private key files (CLI key
//     generation path).
//  2. certs.Cmd (create subcommand) — creates self-signed SCION sensitive-voting,
//     regular-voting, and cp-root certificates via the production cobra
//     command, exercising the IsX509Signer gate in create.go (lines 244, 287).
//  3. trcs.RunSign — signs the TRC payload with the sensitive-voting key.
//  4. trcs.RunSign — signs the TRC payload with the regular-voting key.
//  5. trcs.RunCombine — combines the two partially signed TRCs into a single TRC.
//  6. trcs.RunVerify — verifies the combined TRC (the genuine production verify path).

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/private/app/command"
	"github.com/scionproto/scion/scion-pki/certs"
	"github.com/scionproto/scion/scion-pki/key"
	"github.com/scionproto/scion/scion-pki/trcs"
)

// TestMLDSACLIEndToEnd drives CLI command functions to create a complete
// ML-DSA-65 trust chain on disk and then verifies it via RunVerify.
func TestMLDSACLIEndToEnd(t *testing.T) {
	dir := t.TempDir()

	// -------------------------------------------------------------------------
	// Step 1: Generate ML-DSA-65 private keys using the CLI key command.
	// NewPrivateCmd is the production CLI command; we invoke it exactly as the
	// scion-pki binary does (via cmd.Execute after SetArgs).
	// -------------------------------------------------------------------------
	sensitiveKeyFile := filepath.Join(dir, "sensitive.key")
	regularKeyFile := filepath.Join(dir, "regular.key")
	rootKeyFile := filepath.Join(dir, "root.key")

	for _, kf := range []string{sensitiveKeyFile, regularKeyFile, rootKeyFile} {
		cmd := key.NewPrivateCmd(command.StringPather("scion-pki"))
		cmd.SetArgs([]string{"--curve", "ml-dsa-65", kf})
		require.NoError(t, cmd.Execute(), "key.NewPrivateCmd for %s", kf)
	}

	// -------------------------------------------------------------------------
	// Step 2: Write subject template JSON files for each cert profile.
	// All SCION cert types require isd_as in practice (subjectFromVars always
	// embeds the IA field; a zero IA "0-0" is rejected as wildcard by ValidateCert).
	// -------------------------------------------------------------------------
	votingSubjectFile := filepath.Join(dir, "voting-subject.json")
	votingSubject, err := json.Marshal(map[string]string{
		"common_name": "ML-DSA Voter",
		"isd_as":      "1-1",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(votingSubjectFile, votingSubject, 0o644))

	rootSubjectFile := filepath.Join(dir, "root-subject.json")
	rootSubject, err := json.Marshal(map[string]string{
		"common_name": "ML-DSA Root",
		"isd_as":      "1-1",
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(rootSubjectFile, rootSubject, 0o644))

	// -------------------------------------------------------------------------
	// Step 3: Create SCION voting + root certificates via the production CLI
	// command (certs.Cmd). This exercises the IsX509Signer gate in
	// create.go at lines 244 and 287 — the fix to IsX509Signer (adding
	// *mldsa.PublicKey) is what allows these calls to succeed.
	//
	// We use the --key flag to provide the already-generated private key file,
	// and --not-before / --not-after to control the validity window.
	// -------------------------------------------------------------------------
	notBefore := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	notAfter := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)

	sensitiveCertFile := filepath.Join(dir, "sensitive.crt")
	sensitiveCmd := certs.Cmd(command.StringPather("scion-pki"))
	sensitiveCmd.SetArgs([]string{
		"create",
		votingSubjectFile,
		sensitiveCertFile,
		"--profile", "sensitive-voting",
		"--key", sensitiveKeyFile,
		"--not-before", notBefore,
		"--not-after", notAfter,
		"--force",
	})
	require.NoError(t, sensitiveCmd.Execute(), "certs.Cmd create for sensitive-voting")

	regularCertFile := filepath.Join(dir, "regular.crt")
	regularCmd := certs.Cmd(command.StringPather("scion-pki"))
	regularCmd.SetArgs([]string{
		"create",
		votingSubjectFile,
		regularCertFile,
		"--profile", "regular-voting",
		"--key", regularKeyFile,
		"--not-before", notBefore,
		"--not-after", notAfter,
		"--force",
	})
	require.NoError(t, regularCmd.Execute(), "certs.Cmd create for regular-voting")

	rootCertFile := filepath.Join(dir, "root.crt")
	rootCmd := certs.Cmd(command.StringPather("scion-pki"))
	rootCmd.SetArgs([]string{
		"create",
		rootSubjectFile,
		rootCertFile,
		"--profile", "cp-root",
		"--key", rootKeyFile,
		"--not-before", notBefore,
		"--not-after", notAfter,
		"--force",
	})
	require.NoError(t, rootCmd.Execute(), "certs.Cmd create for cp-root")

	// Verify each cert file was created and is the expected type.
	sensitiveCerts, err := cppki.ReadPEMCerts(sensitiveCertFile)
	require.NoError(t, err)
	require.Len(t, sensitiveCerts, 1)
	sensitiveCertType, err := cppki.ValidateCert(sensitiveCerts[0])
	require.NoError(t, err)
	assert.Equal(t, cppki.Sensitive, sensitiveCertType)

	regularCerts, err := cppki.ReadPEMCerts(regularCertFile)
	require.NoError(t, err)
	require.Len(t, regularCerts, 1)
	regularCertType, err := cppki.ValidateCert(regularCerts[0])
	require.NoError(t, err)
	assert.Equal(t, cppki.Regular, regularCertType)

	rootCerts, err := cppki.ReadPEMCerts(rootCertFile)
	require.NoError(t, err)
	require.Len(t, rootCerts, 1)
	rootCertType, err := cppki.ValidateCert(rootCerts[0])
	require.NoError(t, err)
	assert.Equal(t, cppki.Root, rootCertType)

	// -------------------------------------------------------------------------
	// Step 4: Build and write the TRC payload to disk.
	// -------------------------------------------------------------------------
	trc := cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    addr.ISD(1),
			Serial: 1,
			Base:   1,
		},
		Validity: cppki.Validity{
			NotBefore: sensitiveCerts[0].NotBefore.Add(30 * time.Second),
			NotAfter:  sensitiveCerts[0].NotAfter.Add(-30 * time.Second),
		},
		CoreASes:          []addr.AS{1},
		AuthoritativeASes: []addr.AS{1},
		Quorum:            1,
		Description:       "ML-DSA CLI end-to-end test TRC",
		Certificates: []*x509.Certificate{
			sensitiveCerts[0],
			regularCerts[0],
			rootCerts[0],
		},
	}
	rawTRCPld, err := trc.Encode()
	require.NoError(t, err, "encoding TRC payload")

	pldFile := filepath.Join(dir, "ISD1-B1-S1.pld.der")
	require.NoError(t, os.WriteFile(pldFile, rawTRCPld, 0o644), "writing TRC payload")

	// -------------------------------------------------------------------------
	// Step 5 & 6: Sign the TRC payload with each voting key via RunSign (CLI).
	// RunSign reads key and cert files from disk, signs the payload, writes a
	// partial TRC file, and performs an internal sanity-check verify before
	// returning.
	//
	// We pass explicit output paths (out != "") to avoid the auto-naming path in
	// sign.go:outPath(), which calls ExtractIA on the signer cert — voting certs
	// do not require an IA in their subject.
	// -------------------------------------------------------------------------
	sensitiveTRCFile := filepath.Join(dir, "ISD1-B1-S1.sensitive.trc")
	regularTRCFile := filepath.Join(dir, "ISD1-B1-S1.regular.trc")

	err = trcs.RunSign(pldFile, sensitiveCertFile, sensitiveKeyFile, "", sensitiveTRCFile, "")
	require.NoError(t, err, "RunSign with sensitive voter key")

	err = trcs.RunSign(pldFile, regularCertFile, regularKeyFile, "", regularTRCFile, "")
	require.NoError(t, err, "RunSign with regular voter key")
	require.FileExists(t, sensitiveTRCFile, "partial sensitive TRC file must exist")
	require.FileExists(t, regularTRCFile, "partial regular TRC file must exist")

	// -------------------------------------------------------------------------
	// Step 7: Combine the two partial TRCs via RunCombine (CLI).
	// -------------------------------------------------------------------------
	combinedTRCFile := filepath.Join(dir, "ISD1-B1-S1.trc")
	err = trcs.RunCombine(
		[]string{sensitiveTRCFile, regularTRCFile},
		"",   // no explicit payload reference
		combinedTRCFile,
		"der",
	)
	require.NoError(t, err, "RunCombine must produce a combined TRC")
	require.FileExists(t, combinedTRCFile, "combined TRC file must exist")

	// -------------------------------------------------------------------------
	// Step 8: Verify the combined TRC via RunVerify (CLI).
	//
	// RunVerify → verifyInitial → trc.Verify(nil) (for a base TRC: proof-of-
	// possession) → verifyBundle (checks all signer certificates match the
	// anchor). This exercises the full production verification path for an
	// ML-DSA-signed base TRC from on-disk files.
	// -------------------------------------------------------------------------
	err = trcs.RunVerify([]string{combinedTRCFile}, combinedTRCFile, addr.ISD(0))
	require.NoError(t, err, "RunVerify must pass for ML-DSA-signed base TRC")
}
