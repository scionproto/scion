// MIT License
//
// Copyright (c) 2017 Ben Toews.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package oid

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMLDSAOIDs(t *testing.T) {
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17},
		SignatureAlgorithmMLDSA44,
		"SignatureAlgorithmMLDSA44 OID mismatch",
	)
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18},
		SignatureAlgorithmMLDSA65,
		"SignatureAlgorithmMLDSA65 OID mismatch",
	)
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19},
		SignatureAlgorithmMLDSA87,
		"SignatureAlgorithmMLDSA87 OID mismatch",
	)
}

func TestMLDSASignatureAlgorithmToX509SignatureAlgorithm(t *testing.T) {
	assert.Equal(t,
		x509.MLDSA44,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA44.String()],
		"MLDSA44 x509 mapping mismatch",
	)
	assert.Equal(t,
		x509.MLDSA65,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA65.String()],
		"MLDSA65 x509 mapping mismatch",
	)
	assert.Equal(t,
		x509.MLDSA87,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA87.String()],
		"MLDSA87 x509 mapping mismatch",
	)
}
