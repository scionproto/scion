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

package signed_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/scrypto/signed"
)

// sampleBody is a representative control-plane message body (~typical beacon hop field).
var sampleBody = []byte(`{"isd_as":"1-ff00:0:1","hop_fields":[{"ingress":0,"egress":2,"exp_time":63}]}`)

// algoEntry is a helper that bundles a signer + public key for a benchmark sub-case.
type algoEntry struct {
	name   string
	signer crypto.Signer
	pub    crypto.PublicKey
}

func makeAlgos(tb testing.TB) []algoEntry {
	tb.Helper()

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate ECDSA key: %v", err)
	}

	mldsa44Priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		tb.Fatalf("generate ML-DSA-44 key: %v", err)
	}

	mldsa65Priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		tb.Fatalf("generate ML-DSA-65 key: %v", err)
	}

	mldsa87Priv, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		tb.Fatalf("generate ML-DSA-87 key: %v", err)
	}

	return []algoEntry{
		{"ECDSA-P256", ecPriv, ecPriv.Public()},
		{"ML-DSA-44", mldsa44Priv, mldsa44Priv.Public()},
		{"ML-DSA-65", mldsa65Priv, mldsa65Priv.Public()},
		{"ML-DSA-87", mldsa87Priv, mldsa87Priv.Public()},
	}
}

// BenchmarkSign measures signed.Sign latency per algorithm.
func BenchmarkSign(b *testing.B) {
	algos := makeAlgos(b)
	for _, a := range algos {
		a := a
		b.Run(a.name, func(b *testing.B) {
			algo, err := signed.SelectSignatureAlgorithm(a.pub)
			if err != nil {
				b.Fatalf("SelectSignatureAlgorithm: %v", err)
			}
			hdr := signed.Header{
				SignatureAlgorithm: algo,
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("bench-key-id"),
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := signed.Sign(hdr, sampleBody, a.signer)
				if err != nil {
					b.Fatalf("Sign: %v", err)
				}
			}
		})
	}
}

// BenchmarkVerify measures signed.Verify latency per algorithm.
func BenchmarkVerify(b *testing.B) {
	algos := makeAlgos(b)
	for _, a := range algos {
		a := a
		b.Run(a.name, func(b *testing.B) {
			algo, err := signed.SelectSignatureAlgorithm(a.pub)
			if err != nil {
				b.Fatalf("SelectSignatureAlgorithm: %v", err)
			}
			hdr := signed.Header{
				SignatureAlgorithm: algo,
				Timestamp:          time.Now().UTC(),
				VerificationKeyID:  []byte("bench-key-id"),
			}
			// Pre-sign once so verification is not re-running Sign in the loop.
			signedMsg, err := signed.Sign(hdr, sampleBody, a.signer)
			if err != nil {
				b.Fatalf("Sign (setup): %v", err)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := signed.Verify(signedMsg, a.pub)
				if err != nil {
					b.Fatalf("Verify: %v", err)
				}
			}
		})
	}
}

// TestMLDSASizeReport measures actual on-the-wire sizes and prints a table.
// It always passes; run with -v to see output.
func TestMLDSASizeReport(t *testing.T) {
	type algoMeasurement struct {
		name    string
		pubKey  crypto.PublicKey
		signer  crypto.Signer
		pubSize int
		msgSize int // proto.Size of the full SignedMessage
		sigOnly int // raw Signature field length (used in quadratic model)
		hbSize  int // raw HeaderAndBody field length (used in quadratic model)
	}

	algos := makeAlgos(t)
	measurements := make([]algoMeasurement, 0, len(algos))

	for _, a := range algos {
		algo, err := signed.SelectSignatureAlgorithm(a.pub)
		if err != nil {
			t.Fatalf("SelectSignatureAlgorithm(%s): %v", a.name, err)
		}
		hdr := signed.Header{
			SignatureAlgorithm: algo,
			Timestamp:          time.Now().UTC(),
			VerificationKeyID:  []byte("bench-key-id"),
		}
		signedMsg, err := signed.Sign(hdr, sampleBody, a.signer)
		if err != nil {
			t.Fatalf("Sign(%s): %v", a.name, err)
		}

		// Public key size via PKIX DER marshaling.
		pkixBytes, err := x509.MarshalPKIXPublicKey(a.pub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey(%s): %v", a.name, err)
		}

		measurements = append(measurements, algoMeasurement{
			name:    a.name,
			pubKey:  a.pub,
			signer:  a.signer,
			pubSize: len(pkixBytes),
			msgSize: proto.Size(signedMsg),
			sigOnly: len(signedMsg.Signature),
			hbSize:  len(signedMsg.HeaderAndBody),
		})
	}

	// ---- Print the size table ----
	t.Logf("\n=== ML-DSA Size Report (2026-06-24) ===\n")
	t.Logf("%-14s  %10s  %10s  %10s",
		"Algorithm", "PubKey(B)", "SigOnly(B)", "SignedMsg(B)")
	t.Logf("%-14s  %10s  %10s  %10s",
		"--------------", "----------", "----------", "-----------")
	for _, m := range measurements {
		t.Logf("%-14s  %10d  %10d  %10d",
			m.name, m.pubSize, m.sigOnly, m.msgSize)
	}

	// ---- Modeled path-segment sizes ----
	// A segment containing N hop entries has accumulated sizes as follows.
	// Each hop i (0-indexed) of the segment contributes:
	//   - a HeaderAndBody blob (proto marshaling of the hop entry body + header)
	//   - a signature
	//   - the AS's public key (DER-encoded, embedded in the cert)
	//
	// We model each hop's wire contribution as:
	//   hopSigPubBytes = sigOnly + pubKeySize
	//
	// The info field (segment-level header) is estimated at 32 B for all algos.
	// Total segment bytes ≈ infoSize + sum_{i=1}^{N} (headerAndBodyBase + hopSigPub)
	//
	// headerAndBodyBase: protobuf overhead for each hop entry. For ECDSA the
	// HeaderAndBody blob is ~200 B; for ML-DSA it is larger due to the embedded
	// signature-algorithm field. We use the measured msgSize (which already
	// includes HeaderAndBody + Signature) as the per-hop cost, minus the pubkey
	// which is in the cert rather than inline. So per-hop ≈ msgSize + pubSize
	// (the cert contributes the pubkey on top of the message).
	const (
		infoBytes          = 32  // estimate: segment-level info field
		headerAndBodyExtra = 200 // fixed per-hop overhead (segment-level protobuf fields)
	)

	hopCounts := []int{1, 5, 10, 20}
	grpcLimit := 4 * 1024 * 1024 // 4 MiB

	t.Logf("\n=== Modeled Path-Segment Size (bytes) — ANALYTICAL MODEL ===")
	t.Logf("Per-hop cost = msgSize(SignedMessage) + pubKeySize (cert); segment = info + N×per-hop-cost + N×%dB overhead", headerAndBodyExtra)
	t.Logf("gRPC default message limit: %d B (4 MiB)\n", grpcLimit)

	header := "%-14s"
	for _, h := range hopCounts {
		header += "  %8s"
		_ = h
	}
	headerArgs := []interface{}{"Algorithm"}
	for _, h := range hopCounts {
		headerArgs = append(headerArgs, formatHops(h))
	}
	t.Logf(header, headerArgs...)

	sepLine := "%-14s"
	for range hopCounts {
		sepLine += "  %8s"
	}
	sepArgs := []interface{}{"--------------"}
	for range hopCounts {
		sepArgs = append(sepArgs, "--------")
	}
	t.Logf(sepLine, sepArgs...)

	for _, m := range measurements {
		// Per-hop cost on the wire: SignedMessage proto + cert pubkey.
		perHop := m.msgSize + m.pubSize + headerAndBodyExtra
		rowFmt := "%-14s"
		rowArgs := []interface{}{m.name}
		for _, h := range hopCounts {
			segBytes := infoBytes + h*perHop
			over := ""
			if segBytes > grpcLimit {
				over = "!"
			}
			rowFmt += "  %8s"
			rowArgs = append(rowArgs, formatSize(segBytes, over))
		}
		t.Logf(rowFmt, rowArgs...)
	}
	t.Logf("\n  ! = exceeds gRPC 4 MiB default limit")

	// ---- Quadratic associated-data model for segment signing ----
	// In pkg/segment/seg.go (around line 328), when AS i signs its hop entry,
	// the associated data consists of:
	//   - ps.Info.Raw once per sign call (small, ~32 B; omitted here as negligible)
	//   - for every prior entry j < i: ASEntries[j].Signed.HeaderAndBody AND
	//     ASEntries[j].Signed.Signature
	// So total bytes hashed across all N AS sign calls grows as:
	//   sum_{i=0}^{N-1} i * (perHopHB + perHopSig)  =  N*(N-1)/2 * (HB + Sig)
	// This is the "quadratic hashing cost" for beacon propagation.
	// Note: the Info.Raw term (N * ~32 B) is linear and negligible relative to
	// the quadratic (HB+Sig) term at realistic hop counts.
	t.Logf("\n=== Modeled Cumulative Associated-Data Bytes (quadratic hashing) ===")
	t.Logf("Per AS sign call, associated data = segment Info.Raw (once, ~32B, omitted) +")
	t.Logf("  all prior hops' HeaderAndBody AND Signature (per pkg/segment/seg.go:328).")
	t.Logf("Total bytes hashed across N-hop segment construction = N*(N-1)/2 × (HB+Sig)")
	t.Logf("%-14s  %10s  %10s  %10s  %10s  %10s",
		"Algorithm", "HB(B)", "Sig(B)", "5 hops", "10 hops", "20 hops")
	t.Logf("%-14s  %10s  %10s  %10s  %10s  %10s",
		"--------------", "----------", "----------", "----------", "----------", "----------")
	for _, m := range measurements {
		perHop := m.hbSize + m.sigOnly
		t.Logf("%-14s  %10d  %10d  %10d  %10d  %10d",
			m.name, m.hbSize, m.sigOnly,
			quadAssocData(5, perHop),
			quadAssocData(10, perHop),
			quadAssocData(20, perHop),
		)
	}
	t.Logf("\n  quadAssocData(N, s) = N*(N-1)/2 * s  where s = HB+Sig per prior hop  (MODELED)")
}

func quadAssocData(n, sigBytes int) int {
	return n * (n - 1) / 2 * sigBytes
}

func formatHops(n int) string {
	return formatInt(n) + " hops"
}

func formatInt(n int) string {
	switch n {
	case 1:
		return "1"
	case 5:
		return "5"
	case 10:
		return "10"
	case 20:
		return "20"
	}
	return "?"
}

func formatSize(b int, suffix string) string {
	kb := float64(b) / 1024.0
	if b >= 1024*1024 {
		mb := float64(b) / (1024.0 * 1024.0)
		return formatFloat(mb, "M") + suffix
	}
	if b >= 1024 {
		return formatFloat(kb, "K") + suffix
	}
	return formatDec(b) + suffix
}

func formatFloat(f float64, unit string) string {
	// format to 1 decimal
	i := int(f * 10)
	whole := i / 10
	frac := i % 10
	return formatDec(whole) + "." + formatDec(frac) + unit
}

func formatDec(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

