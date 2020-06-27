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

// Package oid contains OID definitions.
package oid

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// Content types
var (
	ContentTypeData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	ContentTypeSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// SignerInfo attribute types
var (
	AttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	AttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	AttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

// PublicKey algorithms
var (
	PublicKeyAlgorithmRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	PublicKeyAlgorithmECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Digest algorithms
var (
	DigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	DigestAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	DigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	DigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	DigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// Signature algorithms
var (
	SignatureAlgorithmMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	SignatureAlgorithmMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	SignatureAlgorithmSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	SignatureAlgorithmSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	SignatureAlgorithmSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	SignatureAlgorithmSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	SignatureAlgorithmRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	SignatureAlgorithmDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	SignatureAlgorithmDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	SignatureAlgorithmECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	SignatureAlgorithmECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	SignatureAlgorithmECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	SignatureAlgorithmECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	SignatureAlgorithmISOSHA1WithRSA  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

// X.509v3 exetension identifiers.
var (
	ExtensionSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// DigestAlgorithmToCryptoHash maps digest OIDs to crypto.Hash values.
var DigestAlgorithmToCryptoHash = map[string]crypto.Hash{
	DigestAlgorithmSHA1.String():   crypto.SHA1,
	DigestAlgorithmMD5.String():    crypto.MD5,
	DigestAlgorithmSHA256.String(): crypto.SHA256,
	DigestAlgorithmSHA384.String(): crypto.SHA384,
	DigestAlgorithmSHA512.String(): crypto.SHA512,
}

// CryptoHashToDigestAlgorithm maps crypto.Hash values to digest OIDs.
var CryptoHashToDigestAlgorithm = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   DigestAlgorithmSHA1,
	crypto.MD5:    DigestAlgorithmMD5,
	crypto.SHA256: DigestAlgorithmSHA256,
	crypto.SHA384: DigestAlgorithmSHA384,
	crypto.SHA512: DigestAlgorithmSHA512,
}

// X509SignatureAlgorithmToDigestAlgorithm maps x509.SignatureAlgorithm to
// digestAlgorithm OIDs.
var X509SignatureAlgorithmToDigestAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.SHA1WithRSA:     DigestAlgorithmSHA1,
	x509.MD5WithRSA:      DigestAlgorithmMD5,
	x509.SHA256WithRSA:   DigestAlgorithmSHA256,
	x509.SHA384WithRSA:   DigestAlgorithmSHA384,
	x509.SHA512WithRSA:   DigestAlgorithmSHA512,
	x509.ECDSAWithSHA1:   DigestAlgorithmSHA1,
	x509.ECDSAWithSHA256: DigestAlgorithmSHA256,
	x509.ECDSAWithSHA384: DigestAlgorithmSHA384,
	x509.ECDSAWithSHA512: DigestAlgorithmSHA512,
}

// X509SignatureAlgorithmToPublicKeyAlgorithm maps x509.SignatureAlgorithm to
// signatureAlgorithm OIDs.
var X509SignatureAlgorithmToPublicKeyAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.SHA1WithRSA:     PublicKeyAlgorithmRSA,
	x509.MD5WithRSA:      PublicKeyAlgorithmRSA,
	x509.SHA256WithRSA:   PublicKeyAlgorithmRSA,
	x509.SHA384WithRSA:   PublicKeyAlgorithmRSA,
	x509.SHA512WithRSA:   PublicKeyAlgorithmRSA,
	x509.ECDSAWithSHA1:   PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA256: PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA384: PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA512: PublicKeyAlgorithmECDSA,
}

type pkMDToSA map[string]map[string]x509.SignatureAlgorithm

// PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm maps digest and signature
// OIDs to x509.SignatureAlgorithm values.
var PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm = pkMDToSA{
	PublicKeyAlgorithmRSA.String(): map[string]x509.SignatureAlgorithm{
		DigestAlgorithmSHA1.String():   x509.SHA1WithRSA,
		DigestAlgorithmMD5.String():    x509.MD5WithRSA,
		DigestAlgorithmSHA256.String(): x509.SHA256WithRSA,
		DigestAlgorithmSHA384.String(): x509.SHA384WithRSA,
		DigestAlgorithmSHA512.String(): x509.SHA512WithRSA,
	},
	PublicKeyAlgorithmECDSA.String(): map[string]x509.SignatureAlgorithm{
		DigestAlgorithmSHA1.String():   x509.ECDSAWithSHA1,
		DigestAlgorithmSHA256.String(): x509.ECDSAWithSHA256,
		DigestAlgorithmSHA384.String(): x509.ECDSAWithSHA384,
		DigestAlgorithmSHA512.String(): x509.ECDSAWithSHA512,
	},
}

// SignatureAlgorithmToX509SignatureAlgorithm maps signature algorithm OIDs to
// x509.SignatureAlgorithm values.
var SignatureAlgorithmToX509SignatureAlgorithm = map[string]x509.SignatureAlgorithm{
	SignatureAlgorithmSHA1WithRSA.String():     x509.SHA1WithRSA,
	SignatureAlgorithmMD5WithRSA.String():      x509.MD5WithRSA,
	SignatureAlgorithmSHA256WithRSA.String():   x509.SHA256WithRSA,
	SignatureAlgorithmSHA384WithRSA.String():   x509.SHA384WithRSA,
	SignatureAlgorithmSHA512WithRSA.String():   x509.SHA512WithRSA,
	SignatureAlgorithmECDSAWithSHA1.String():   x509.ECDSAWithSHA1,
	SignatureAlgorithmECDSAWithSHA256.String(): x509.ECDSAWithSHA256,
	SignatureAlgorithmECDSAWithSHA384.String(): x509.ECDSAWithSHA384,
	SignatureAlgorithmECDSAWithSHA512.String(): x509.ECDSAWithSHA512,
	SignatureAlgorithmDSAWithSHA1.String():     x509.DSAWithSHA1,
}

type pkToPKIX map[x509.PublicKeyAlgorithm]pkix.AlgorithmIdentifier

// X509PublicKeyAlgorithmToPKIXAlgorithmIdentifier maps certificate public key
// algorithms to CMS signature algorithms.
var X509PublicKeyAlgorithmToPKIXAlgorithmIdentifier = pkToPKIX{
	x509.RSA:   pkix.AlgorithmIdentifier{Algorithm: PublicKeyAlgorithmRSA},
	x509.ECDSA: pkix.AlgorithmIdentifier{Algorithm: PublicKeyAlgorithmECDSA},
}
