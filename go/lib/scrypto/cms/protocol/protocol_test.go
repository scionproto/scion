package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/scionproto/scion/go/lib/scrypto/cms/oid"
)

func TestSignerInfo(t *testing.T) {
	priv, cert, err := pkcs12.Decode(fixturePFX, "asdf")
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello, world!")

	eci, err := NewEncapsulatedContentInfo(oid.ContentTypeData, msg)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := NewSignedData(eci)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{cert}
	if err = sd.AddSignerInfo(chain, priv.(*ecdsa.PrivateKey)); err != nil {
		t.Fatal(err)
	}

	der, err := sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}

	ci, err := ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err := sd2.EncapContentInfo.DataEContent()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, msg2) {
		t.Fatal()
	}

	// Make detached
	sd.EncapContentInfo.EContent = asn1.RawValue{}

	der, err = sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}

	ci, err = ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err = ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	msg2, err = sd2.EncapContentInfo.DataEContent()
	if err != nil {
		t.Fatal(err)
	}
	if msg2 != nil {
		t.Fatal()
	}
}

func TestEncapsulatedContentInfo(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	oldECI := sd.EncapContentInfo

	oldData, err := oldECI.DataEContent()
	if err != nil {
		t.Fatal(err)
	}

	newECI, err := NewEncapsulatedContentInfo(oid.ContentTypeData, oldData)
	if err != nil {
		t.Fatal(err)
	}

	newData, err := newECI.DataEContent()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldData, newData) {
		t.Fatal("ECI data round trip mismatch: ", oldData, " != ", newData)
	}

	oldDER, err := asn1.Marshal(oldECI)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newECI)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("ECI round trip mismatch: ", oldDER, " != ", newDER)
	}
}

func TestMessageDigestAttribute(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]

	oldAttrVal, err := si.GetMessageDigestAttribute()
	if err != nil {
		t.Fatal(err)
	}

	var oldAttr Attribute
	for _, attr := range si.SignedAttrs {
		if attr.Type.Equal(oid.AttributeMessageDigest) {
			oldAttr = attr
			break
		}
	}

	newAttr, err := NewAttribute(oid.AttributeMessageDigest, oldAttrVal)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldAttr.RawValue.Bytes, newAttr.RawValue.Bytes) {
		t.Fatal("raw value mismatch")
	}

	oldDER, err := asn1.Marshal(oldAttr)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newAttr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("der mismatch")
	}
}

func TestContentTypeAttribute(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]

	oldAttrVal, err := si.GetContentTypeAttribute()
	if err != nil {
		t.Fatal(err)
	}

	var oldAttr Attribute
	for _, attr := range si.SignedAttrs {
		if attr.Type.Equal(oid.AttributeContentType) {
			oldAttr = attr
			break
		}
	}

	newAttr, err := NewAttribute(oid.AttributeContentType, oldAttrVal)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldAttr.RawValue.Bytes, newAttr.RawValue.Bytes) {
		t.Fatal("raw value mismatch")
	}

	oldDER, err := asn1.Marshal(oldAttr)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newAttr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("der mismatch")
	}
}

func TestSigningTimeAttribute(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]

	oldAttrVal, err := si.GetSigningTimeAttribute()
	if err != nil {
		t.Fatal(err)
	}

	var oldAttr Attribute
	for _, attr := range si.SignedAttrs {
		if attr.Type.Equal(oid.AttributeSigningTime) {
			oldAttr = attr
			break
		}
	}

	newAttr, err := NewAttribute(oid.AttributeSigningTime, oldAttrVal)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldAttr.RawValue.Bytes, newAttr.RawValue.Bytes) {
		t.Fatal("raw value mismatch")
	}

	oldDER, err := asn1.Marshal(oldAttr)
	if err != nil {
		t.Fatal(err)
	}

	newDER, err := asn1.Marshal(newAttr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("der mismatch")
	}
}

func TestIssuerAndSerialNumber(t *testing.T) {
	ci, _ := ParseContentInfo(fixtureSignatureOpenSSLAttached)
	sd, _ := ci.SignedDataContent()
	si := sd.SignerInfos[0]
	certs, _ := sd.X509Certificates()
	cert, _ := si.FindCertificate(certs)

	newISN, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		t.Fatal(err)
	}

	oldDER, _ := asn1.Marshal(si.SID)
	newDER, _ := asn1.Marshal(newISN)

	if !bytes.Equal(oldDER, newDER) {
		t.Fatal("SID mismatch")
	}
}

func TestParseSignatureOne(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOne)
}

func TestParseSignatureGPGSMAttached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureGPGSMAttached)
}

func TestParseSignatureGPGSM(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureGPGSM)
}

func TestParseSignatureNoCertsGPGSM(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureNoCertsGPGSM)
}

func TestParseSignatureOpenSSLAttached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOpenSSLAttached)
}

func TestParseSignatureOpenSSLDetached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOpenSSLDetached)
}

func TestParseSignautreOutlookDetached(t *testing.T) {
	testParseContentInfo(t, fixtureSignatureOutlookDetached)
}

func testParseContentInfo(t *testing.T, der []byte) {
	ci, err := ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}

	if !sd.EncapContentInfo.IsTypeData() {
		t.Fatal("expected id-data econtent")
	}

	if !sd.EncapContentInfo.EContentType.Equal(oid.ContentTypeData) {
		t.Fatalf("expected %s content, got %s", oid.ContentTypeData.String(),
			sd.EncapContentInfo.EContentType.String())
	}

	data, err := sd.EncapContentInfo.DataEContent()
	if err != nil {
		t.Fatal(err)
	}
	if data != nil && len(data) == 0 {
		t.Fatal("attached signature with zero length data")
	}

	for _, si := range sd.SignerInfos {
		if _, err = si.FindCertificate(certs); err != nil && len(certs) > 0 {
			t.Fatal(err)
		}

		if ct, errr := si.GetContentTypeAttribute(); errr != nil {
			t.Fatal(errr)
		} else {
			// signerInfo contentType attribute must match signedData
			// encapsulatedContentInfo content type.
			if !ct.Equal(sd.EncapContentInfo.EContentType) {
				t.Fatalf("expected %s content, got %s",
					sd.EncapContentInfo.EContentType.String(), ct.String())
			}
		}

		if md, errr := si.GetMessageDigestAttribute(); errr != nil {
			t.Fatal(errr)
		} else if len(md) == 0 {
			t.Fatal("nil/empty message digest attribute")
		}

		if algo := si.X509SignatureAlgorithm(); algo == x509.UnknownSignatureAlgorithm {
			t.Fatalf("unknown signature algorithm")
		}

		var nilTime time.Time
		if st, errr := si.GetSigningTimeAttribute(); errr != nil {
			t.Fatal(errr)
		} else if st == nilTime {
			t.Fatal("0 value signing time")
		}
	}

	der2, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded contentInfo doesn't match original")
	}

	// round trip signedData
	der = ci.Content.Bytes

	der2, err = asn1.Marshal(*sd)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(der, der2) {
		t.Fatal("re-encoded signedData doesn't match original")
	}
}

var fixtureSignatureOne = mustBase64Decode("" +
	"MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B" +
	"BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG" +
	"SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh" +
	"cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB" +
	"Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw" +
	"gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP" +
	"J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF" +
	"a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw" +
	"DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8" +
	"zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+" +
	"L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy" +
	"axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD" +
	"bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI" +
	"hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4" +
	"LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG" +
	"SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX" +
	"iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM" +
	"FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS",
)

var fixtureSignatureGPGSMAttached = mustBase64Decode("" +
	"MIIFgQYJKoZIhvcNAQcCoIIFcjCCBW4CAQExDzANBglghkgBZQMEAgEFADAXBgkq" +
	"hkiG9w0BBwGgCiQIBAZoZWxsbwqgggNYMIIDVDCCAjygAwIBAgIIFnTa5+xvrkgw" +
	"DQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAxMJQmVuIFRvZXdzMCAXDTE3MTExNjE3" +
	"NTAzMloYDzIwNjMwNDA1MTcwMDAwWjAUMRIwEAYDVQQDEwlCZW4gVG9ld3MwggEi" +
	"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdcejAkkPekPH6VuFbDcbkf5XD" +
	"jCAYW3JWlc+tyVpBXoOtDdETKFUQqXxxm2ukLZlRuz/+AugtaijRmgr2boPYzL6v" +
	"rHuPQVlNl327QkIqaia67HEWmy/9puil+d05gzg3Y5H2VrkIqzlZieTzIbFAfnyR" +
	"1KAwvC5yF0Oa60AH6rWg67JAjxzE37j/bBAsUhvNtWPbZ+mSHrAgYE6tQYts9V5x" +
	"82rlOP8d6V49CRSQ59HgMsJK7P6mrhkp1TAbAU4fIIZoyKBi3JZsCMTExz+xAM+g" +
	"2dT+W5JPom9izbdzF4Zj8PH95nf2Dlvf9dtlvAXVkePVozeyAmxNMo5kJbAJAgMB" +
	"AAGjgacwgaQwbgYDVR0RBGcwZYEUbWFzdGFoeWV0aUBnbWFpbC5jb22BFW1hc3Rh" +
	"aHlldGlAZ2l0aHViLmNvbYERYnRvZXdzQGdpdGh1Yi5jb22BI21hc3RhaHlldGlA" +
	"dXNlcnMubm9yZXBseS5naXRodWIuY29tMBEGCisGAQQB2kcCAgEEAwEB/zAPBgNV" +
	"HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEA" +
	"iurKpC6lhIEEsqkpN65zqUhnWijgf6jai1TlM59PYhYNduGoscoMZsvgI22ONLVu" +
	"DguY0zQdGOI31TugdkCvd0728Eu1rwZVzJx4z6vM0CjCb1FluDMqGXJt7PSXz92T" +
	"CeybmkkgQqiR9eoJUJPi9C+Lrwi4aOfFiwutvsGw9HB+n5EOVCj+tE0jbnraY323" +
	"nj2Ibfo/ZGPzXpwSJMimma0Qa9IF5CKBGkbZWPRCi/l5vfDEcqy7od9KmIW7WKAu" +
	"aNjW5c0Zgu4ZufRYpiN8IEkvnAXH5WAFWSKlQslu5zVgqSoB7T8pu211OTWBdDgu" +
	"LGuzzactHfA/HTr9d5LNrzGCAeEwggHdAgEBMCAwFDESMBAGA1UEAxMJQmVuIFRv" +
	"ZXdzAggWdNrn7G+uSDANBglghkgBZQMEAgEFAKCBkzAYBgkqhkiG9w0BCQMxCwYJ" +
	"KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzExMjIxNzU3NTZaMCgGCSqGSIb3" +
	"DQEJDzEbMBkwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMC8GCSqGSIb3DQEJBDEi" +
	"BCBYkbW1ItXfCG0P8LEQ+9nSG7T8cWOvNNCChqLoRva+AzANBgkqhkiG9w0BAQEF" +
	"AASCAQBbKSOFVXnWuRADFW1M9mZApLKjU2jtzN22aaVTlvSDoHE7yzj53EVorfm4" +
	"br1JWJMeOJcfAiV5oiJiuIqiXOec5bTgR9EzkCZ8yA+R89y6M538XXp8sLMxNkO/" +
	"EhoLXdQV8UhoF2mXktbbe/blTODvupTBonUXQhVAeJpWi0q8Qaz5StpzuXu6UFWK" +
	"nTCTsl8gg1x/Wf0zLOUVWtLLPLeQB5usv1fQker0e+kCthv/q+QyLxw9J3e5rJ9a" +
	"Dekeh5WkaS8yHCCvnOyOLI9/o2rHwUII36XjvK6VF+UHG+OcoL29BnUb01+vwxPk" +
	"SDXMwnexRO3w39tu4ChUFbsX8l5C",
)

var fixtureSignatureGPGSM = mustBase64Decode("" +
	"MIIFdQYJKoZIhvcNAQcCoIIFZjCCBWICAQExDzANBglghkgBZQMEAgEFADALBgkq" +
	"hkiG9w0BBwGgggNYMIIDVDCCAjygAwIBAgIIFnTa5+xvrkgwDQYJKoZIhvcNAQEL" +
	"BQAwFDESMBAGA1UEAxMJQmVuIFRvZXdzMCAXDTE3MTExNjE3NTAzMloYDzIwNjMw" +
	"NDA1MTcwMDAwWjAUMRIwEAYDVQQDEwlCZW4gVG9ld3MwggEiMA0GCSqGSIb3DQEB" +
	"AQUAA4IBDwAwggEKAoIBAQCdcejAkkPekPH6VuFbDcbkf5XDjCAYW3JWlc+tyVpB" +
	"XoOtDdETKFUQqXxxm2ukLZlRuz/+AugtaijRmgr2boPYzL6vrHuPQVlNl327QkIq" +
	"aia67HEWmy/9puil+d05gzg3Y5H2VrkIqzlZieTzIbFAfnyR1KAwvC5yF0Oa60AH" +
	"6rWg67JAjxzE37j/bBAsUhvNtWPbZ+mSHrAgYE6tQYts9V5x82rlOP8d6V49CRSQ" +
	"59HgMsJK7P6mrhkp1TAbAU4fIIZoyKBi3JZsCMTExz+xAM+g2dT+W5JPom9izbdz" +
	"F4Zj8PH95nf2Dlvf9dtlvAXVkePVozeyAmxNMo5kJbAJAgMBAAGjgacwgaQwbgYD" +
	"VR0RBGcwZYEUbWFzdGFoeWV0aUBnbWFpbC5jb22BFW1hc3RhaHlldGlAZ2l0aHVi" +
	"LmNvbYERYnRvZXdzQGdpdGh1Yi5jb22BI21hc3RhaHlldGlAdXNlcnMubm9yZXBs" +
	"eS5naXRodWIuY29tMBEGCisGAQQB2kcCAgEEAwEB/zAPBgNVHRMBAf8EBTADAQH/" +
	"MA4GA1UdDwEB/wQEAwIE8DANBgkqhkiG9w0BAQsFAAOCAQEAiurKpC6lhIEEsqkp" +
	"N65zqUhnWijgf6jai1TlM59PYhYNduGoscoMZsvgI22ONLVuDguY0zQdGOI31Tug" +
	"dkCvd0728Eu1rwZVzJx4z6vM0CjCb1FluDMqGXJt7PSXz92TCeybmkkgQqiR9eoJ" +
	"UJPi9C+Lrwi4aOfFiwutvsGw9HB+n5EOVCj+tE0jbnraY323nj2Ibfo/ZGPzXpwS" +
	"JMimma0Qa9IF5CKBGkbZWPRCi/l5vfDEcqy7od9KmIW7WKAuaNjW5c0Zgu4ZufRY" +
	"piN8IEkvnAXH5WAFWSKlQslu5zVgqSoB7T8pu211OTWBdDguLGuzzactHfA/HTr9" +
	"d5LNrzGCAeEwggHdAgEBMCAwFDESMBAGA1UEAxMJQmVuIFRvZXdzAggWdNrn7G+u" +
	"SDANBglghkgBZQMEAgEFAKCBkzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG" +
	"CSqGSIb3DQEJBTEPFw0xNzExMTcwMDQ3MjRaMCgGCSqGSIb3DQEJDzEbMBkwCwYJ" +
	"YIZIAWUDBAECMAoGCCqGSIb3DQMHMC8GCSqGSIb3DQEJBDEiBCBNyg/V9CSjGwOr" +
	"gHy6536zK/LQie7RzuFUs6/tRY3g3DANBgkqhkiG9w0BAQEFAASCAQBh+60EcdyD" +
	"7iWz6xYxK71Fr4IfH0vbNJiiN/zT4FIcdoLtU6T3U6evC2vClA2zeI0VWfKOfVp8" +
	"zff0qOZqXNAHKVZaJSG+Af6kDJAQC8ejuZxxP5a+6K10FlDzN4klBwLHDWWza/fJ" +
	"PGAXZYX2q63Xqwvu593SzoTcKc9/kk1a+peXM7lzqoIHG8DjA24OKP34iNoZunhu" +
	"/aw7HTCdzaDGJxFEVLbCtDn30jKZ27InxMkb4ikBtCwuJ3qjCRspZurmDl38zbAm" +
	"z9djDFaL7cYFBLJBNmlPVHzz6rZuh+vUIHLrFMcaBAsVon8nVTm2P3YuZuRRjgsz" +
	"+G/kBkl/nbuk",
)

var fixtureSignatureNoCertsGPGSM = mustBase64Decode("" +
	"MIICGQYJKoZIhvcNAQcCoIICCjCCAgYCAQExDzANBglghkgBZQMEAgEFADALBgkq" +
	"hkiG9w0BBwExggHhMIIB3QIBATAgMBQxEjAQBgNVBAMTCUJlbiBUb2V3cwIIFnTa" +
	"5+xvrkgwDQYJYIZIAWUDBAIBBQCggZMwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH" +
	"ATAcBgkqhkiG9w0BCQUxDxcNMTcxMTE3MDA0MTQ4WjAoBgkqhkiG9w0BCQ8xGzAZ" +
	"MAsGCWCGSAFlAwQBAjAKBggqhkiG9w0DBzAvBgkqhkiG9w0BCQQxIgQgTcoP1fQk" +
	"oxsDq4B8uud+syvy0Inu0c7hVLOv7UWN4NwwDQYJKoZIhvcNAQEBBQAEggEALxgB" +
	"jzGh96EYjQ1NABiFco11K2fINlUWsxgk7rjtAjxlgQ2wbrrwnj7lk3XXL+Shx8q2" +
	"DtMlA8Xq4FYYdRFyLDiLR2yekHjLLZmPFG+xxpuEq3bZtzDEhHtuM0Ziiucrz33m" +
	"ml3m+jAEil71YlP4/VQ8FGdghT1Mz6vA5Uuo+MOnWqX6YRRjdcCVdwAy1M1JE131" +
	"0OexxFlCnW8YHLsgR+3i4WaSgFz99YkSptm+3VedEq7kQqjWGTqfG1EOe2wto3pb" +
	"NHc0HREEu+jvwx+nkN/zoL6ZkfAY5bowPNrYI6j+349EuwsNlZT6nHstIqkZgJoj" +
	"tqsziCgGMzJMVq+4lA==",
)

var fixtureSignatureOpenSSLAttached = mustBase64Decode("" +
	"MIIFGgYJKoZIhvcNAQcCoIIFCzCCBQcCAQExDzANBglghkgBZQMEAgEFADAcBgkq" +
	"hkiG9w0BBwGgDwQNaGVsbG8sIHdvcmxkIaCCAqMwggKfMIIBh6ADAgECAgEAMA0G" +
	"CSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCGNtcy10ZXN0MB4XDTE3MTEyMDIwNTM0" +
	"M1oXDTI3MTExODIwNTM0M1owEzERMA8GA1UEAwwIY21zLXRlc3QwggEiMA0GCSqG" +
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWMRnJdRQxw8j8Yn3jh/rcZyeALStl+MmM" +
	"TEtr6XsmMOWQhnP6nCAIOw5EIAXGpKl4Yg3F2gDKmJCVl279Q+G9nLtvmWvCzu19" +
	"BJUG7jVLWzO8KSuJa83iiilZUP2adVZujdGB6dxekIBu7vkYi9XxZJm4edhj0bkd" +
	"EtkxLCNUGDQKsywnKOTWzfefT9UCQJyLwt74ThJtNX7uoYrfAHNfBARk3Kx+wf4U" +
	"Grd2GmSe8Lnr3FNcZ/uMJffsYvBk3fbDwYsVC6rd4BuJvvri3K1dti3rnvDEnuMI" +
	"Ve7a2n7NE7yV0cietIjKeeY8bO25lwrTtBzgP5y1G9spjzAtiRLZAgMBAAEwDQYJ" +
	"KoZIhvcNAQEFBQADggEBAMkYPFmsHYlyO+KZMKEWUWOdw1rwrIVhLQOKqLz8Wbe8" +
	"lIQ5pdsd4S1DqvMEzYyMtpZckZ9mOBZh/SQsmdb8sZnQwiMvlPSO6IWp/MpuP+VK" +
	"v8IBAr1aaLlMaelV086uIFc9coE6XAdWFrGlUT9FYM00JwoSfi51vbcqbIh6P8y9" +
	"uwHqlt2vkVYujto+p0UMBnBZkfKBgzMG7ILWpJbVszmpesVzI2XUgq8BxlO0fvw5" +
	"m/R4bAtHqXTK0xVrTBXUg6izFbdA3pVlFMiuv8Kq2cyBg+VkXGYmZ37BGhApe5Le" +
	"Dabe4iGcXQMW4lunjRSv8gDu/ODA/20OMNVDOx92MTIxggIqMIICJgIBATAYMBMx" +
	"ETAPBgNVBAMMCGNtcy10ZXN0AgEAMA0GCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3" +
	"DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTEyMDIwNTM0M1ow" +
	"LwYJKoZIhvcNAQkEMSIEIGjmVrJR5n6DWL74SDqw1RxmGfPnoanw51g41B/zaPco" +
	"MHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglg" +
	"hkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMC" +
	"AgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJHB" +
	"kfH1hZ4Y0TI6PdW7DNFnb++KQJiu4NmzE7SyTJOCxC2W44uAKUdJw7c8cdn/lcb/" +
	"y1kvwNbi2kysuZSTpywBIjHSTw3BTwdaNJFd6HUV1mX2IQRfaJIPW5fqkhLfQtZ6" +
	"LZka/HWQ5fwA51g6lVNTMbStjsPlBef6qEDcCLMp/4CNEqC5+fUx8Jb7Q5mvyCHQ" +
	"3IZrIEMLBYhrgrm61qh/MXKnAqlEo6XxN1fL0CXDxy9dYPSKr2G66o9+BjmYktF5" +
	"3MfxrT4JDizd2S/8BVEv+H+uHmrpyRxMceREPJVrVHOdd922hyKALbAGcoyMdXpj" +
	"ZdMtHnR5z07z9wxvwiw=",
)

var fixtureSignatureOpenSSLDetached = mustBase64Decode("" +
	"MIIFGgYJKoZIhvcNAQcCoIIFCzCCBQcCAQExDzANBglghkgBZQMEAgEFADAcBgkq" +
	"hkiG9w0BBwGgDwQNaGVsbG8sIHdvcmxkIaCCAqMwggKfMIIBh6ADAgECAgEAMA0G" +
	"CSqGSIb3DQEBBQUAMBMxETAPBgNVBAMMCGNtcy10ZXN0MB4XDTE3MTEyMDIwNTM0" +
	"M1oXDTI3MTExODIwNTM0M1owEzERMA8GA1UEAwwIY21zLXRlc3QwggEiMA0GCSqG" +
	"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWMRnJdRQxw8j8Yn3jh/rcZyeALStl+MmM" +
	"TEtr6XsmMOWQhnP6nCAIOw5EIAXGpKl4Yg3F2gDKmJCVl279Q+G9nLtvmWvCzu19" +
	"BJUG7jVLWzO8KSuJa83iiilZUP2adVZujdGB6dxekIBu7vkYi9XxZJm4edhj0bkd" +
	"EtkxLCNUGDQKsywnKOTWzfefT9UCQJyLwt74ThJtNX7uoYrfAHNfBARk3Kx+wf4U" +
	"Grd2GmSe8Lnr3FNcZ/uMJffsYvBk3fbDwYsVC6rd4BuJvvri3K1dti3rnvDEnuMI" +
	"Ve7a2n7NE7yV0cietIjKeeY8bO25lwrTtBzgP5y1G9spjzAtiRLZAgMBAAEwDQYJ" +
	"KoZIhvcNAQEFBQADggEBAMkYPFmsHYlyO+KZMKEWUWOdw1rwrIVhLQOKqLz8Wbe8" +
	"lIQ5pdsd4S1DqvMEzYyMtpZckZ9mOBZh/SQsmdb8sZnQwiMvlPSO6IWp/MpuP+VK" +
	"v8IBAr1aaLlMaelV086uIFc9coE6XAdWFrGlUT9FYM00JwoSfi51vbcqbIh6P8y9" +
	"uwHqlt2vkVYujto+p0UMBnBZkfKBgzMG7ILWpJbVszmpesVzI2XUgq8BxlO0fvw5" +
	"m/R4bAtHqXTK0xVrTBXUg6izFbdA3pVlFMiuv8Kq2cyBg+VkXGYmZ37BGhApe5Le" +
	"Dabe4iGcXQMW4lunjRSv8gDu/ODA/20OMNVDOx92MTIxggIqMIICJgIBATAYMBMx" +
	"ETAPBgNVBAMMCGNtcy10ZXN0AgEAMA0GCWCGSAFlAwQCAQUAoIHkMBgGCSqGSIb3" +
	"DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE3MTEyMDIwNTM0M1ow" +
	"LwYJKoZIhvcNAQkEMSIEIGjmVrJR5n6DWL74SDqw1RxmGfPnoanw51g41B/zaPco" +
	"MHkGCSqGSIb3DQEJDzFsMGowCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBFjALBglg" +
	"hkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMC" +
	"AgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMA0GCSqGSIb3DQEBAQUABIIBAJHB" +
	"kfH1hZ4Y0TI6PdW7DNFnb++KQJiu4NmzE7SyTJOCxC2W44uAKUdJw7c8cdn/lcb/" +
	"y1kvwNbi2kysuZSTpywBIjHSTw3BTwdaNJFd6HUV1mX2IQRfaJIPW5fqkhLfQtZ6" +
	"LZka/HWQ5fwA51g6lVNTMbStjsPlBef6qEDcCLMp/4CNEqC5+fUx8Jb7Q5mvyCHQ" +
	"3IZrIEMLBYhrgrm61qh/MXKnAqlEo6XxN1fL0CXDxy9dYPSKr2G66o9+BjmYktF5" +
	"3MfxrT4JDizd2S/8BVEv+H+uHmrpyRxMceREPJVrVHOdd922hyKALbAGcoyMdXpj" +
	"ZdMtHnR5z07z9wxvwiw=",
)

var fixtureSignatureOutlookDetached = mustBase64Decode("" +
	"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" +
	"BgEFBQcDAgYIKwYBBQUHAwQwQwYDVR0gBDwwOjA4BgpghkgBhv1sBAECMCowKAYI" +
	"KwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgYgGA1UdHwSB" +
	"gDB+MD2gO6A5hjdodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEy" +
	"QXNzdXJlZElEQ0EtZzIuY3JsMD2gO6A5hjdodHRwOi8vY3JsNC5kaWdpY2VydC5j" +
	"b20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ0EtZzIuY3JsMHkGCCsGAQUFBwEBBG0w" +
	"azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF" +
	"BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNz" +
	"dXJlZElEQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQA4dg2Bn5/tXoNtXU2t+ImZ" +
	"biMgHLRv0tt2wi5yUk4T24gn2YBpCq/Qauk0ieKkH7KriAe3DuOpifrcxy+e9MQL" +
	"CeKQu890YQXcyo/bk+mVBMXR0LNhaD41Obk9VIah7+0/amKevPV6WdsTyx+fUsCw" +
	"EiFZ6EBSEtDCk/ADemYCsQ1g2BFMkXxkMcQ236loZ3B9KsU9tJr/E57yDKNp4LAg" +
	"WX6SXL/bty4o5w+7lQmdqkSCZJie7NXqBnNOXGfuzXgPLwtvAYBntrLzFJUSJ2jb" +
	"DA1AZosyOMeg50vLlZV9tigHTzC/TbzznwhgqIQ3r2YAkjMf6Jx/n6APqzgp4JEf" +
	"MIIGTjCCBTagAwIBAgIQBK55YGZmkBq5xX+mbFvczTANBgkqhkiG9w0BAQsFADBl" +
	"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3" +
	"d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv" +
	"b3QgQ0EwHhcNMTMxMTA1MTIwMDAwWhcNMjgxMTA1MTIwMDAwWjBlMQswCQYDVQQG" +
	"EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl" +
	"cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ0EwggEi" +
	"MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDc+BEjP2q178AneRstBYeiEEMx" +
	"3w7UFRtPd6Qizj6McPC+B47dJyq8AR22LArK3WlYH0HtagUf2mN4WR4iLCv4un7J" +
	"NTtW8R98Qn4lsCMZxkU41z1E+SB8YK4csFoYBL6PO/ep8JSapgxjSbZBF1NAMr1P" +
	"5lB6UB8lRejxia/N/17/UPPwFxH/vcWJ9b1iudj7jkUEhW2ZzcVITf0mqwI2Reo2" +
	"119q4hqCQQrc6dn1kReOxiGtODwT5h5/ZpzVTdlG2vbPUqd9OyTDtMFRNcab69Tv" +
	"fuR7A+FEvXoLN+BPy4KKDXEY5KbgiSwb87JzPMGwkp4Yfb2rfcV9CKEswp9zAgMB" +
	"AAGjggL4MIIC9DASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjA0" +
	"BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0" +
	"LmNvbTCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29t" +
	"L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMu" +
	"ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHSUE" +
	"FjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwggGzBgNVHSAEggGqMIIBpjCCAaIGCmCG" +
	"SAGG/WwAAgQwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j" +
	"b20vQ1BTMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBm" +
	"ACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABp" +
	"AHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAg" +
	"AEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAg" +
	"AFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAg" +
	"AHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBu" +
	"AGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBp" +
	"AG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMB0GA1UdDgQWBBTnAiOAAE/Y" +
	"17yUC9k/dDlJMjyKeTAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAN" +
	"BgkqhkiG9w0BAQsFAAOCAQEATtSJJ7n9HYd3fg8oBZDxCi/JOz69k5yQxq/6kVGH" +
	"MlRr6MrBcVFcmY61+uBiGZmmB5p8Eyfb5QKihBLZFfYKRFfENI9tcx861qABPd7j" +
	"guRFa7LrJf2AXh05kL5bQvbOkWDj+aBWDEgQzjNoe82Tq/Bqy09YD7l7XRsEgZ6n" +
	"IuJXSSfukpMIvmkIUwI6Ll3IGfRQgE4C2bBdkbSTh/mWloFVQI5m7YLYuyhf7Uxh" +
	"7QZYKBlTEUS8RyApsgRs2IlUmTt122d4LB6SeMZVPVgSETJuvUMMTTTbe8ZC2+y+" +
	"q5thTAaS447fISpQVwTAYKI11SSeZjcJSc/V+GWz4OJuwjGCA78wggO7AgEBMHkw" +
	"ZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ" +
	"d3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgU0hBMiBBc3N1cmVk" +
	"IElEIENBAhAFpM7wli8NcSUqUhiUkyhwMA0GCWCGSAFlAwQCAQUAoIICFzAYBgkq" +
	"hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzExMjkxNDQz" +
	"MTlaMC8GCSqGSIb3DQEJBDEiBCBIAYwojIWSwXr3x4np0nnNdWDRPj+z0neCQ8Hw" +
	"kAq8FjCBiAYJKwYBBAGCNxAEMXsweTBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM" +
	"RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD" +
	"ExtEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ0ECEAWkzvCWLw1xJSpSGJSTKHAw" +
	"gYoGCyqGSIb3DQEJEAILMXugeTBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln" +
	"aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE" +
	"aWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ0ECEAWkzvCWLw1xJSpSGJSTKHAwgZMG" +
	"CSqGSIb3DQEJDzGBhTCBgjALBglghkgBZQMEASowCwYJYIZIAWUDBAEWMAoGCCqG" +
	"SIb3DQMHMAsGCWCGSAFlAwQBAjAOBggqhkiG9w0DAgICAIAwDQYIKoZIhvcNAwIC" +
	"AUAwCwYJYIZIAWUDBAIBMAsGCWCGSAFlAwQCAzALBglghkgBZQMEAgIwBwYFKw4D" +
	"AhowDQYJKoZIhvcNAQEBBQAEggEAYQI5FHffEouyysRC1ncGPMq6q3yutScVUsUm" +
	"PwZBd8Uv9EG0DFPWPtFdt5yV+cpmpoAnfcjU3TWqVQ+Ds6FV35k6ndfwA99DNWtQ" +
	"nQVaDRlfF+FL/GdXwJeTDfumLdQniLp9/YL5LrQIFJrwla4xTfoA+hh/lU0DRh69" +
	"8MXZrS/RfFnjRAr6VYGBDKp2Ea2B8OAenriUbMuFJweEsv6IFdXpZIqcQm6kaLz1" +
	"NaVXioZH2LkZbC8GwcEDyr83H1FN2SbmuCNwCij8ZanWPLj+9gOYjmw0y/JB4UkT" +
	"LVVR6K7lc4CT2fvTH7M+NXjOKSUjwymT2A/ax+nFCiSPMRJ5gg==",
)

var fixturePFX = mustBase64Decode("" +
	"MIIDIgIBAzCCAugGCSqGSIb3DQEHAaCCAtkEggLVMIIC0TCCAccGCSqGSIb3DQEH" +
	"BqCCAbgwggG0AgEAMIIBrQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIhJhq" +
	"IE0wYvgCAggAgIIBgFfQz7+5T0RBGtlNHUjM+WmjJFPPhljOcl5vSEFWi2mNpSuU" +
	"IcaNQlhUTxBX7hUJRq6eW3J5T20hY3WBomC6cy4sRpAZlOSDo/UYrQG6YIFc+X97" +
	"t8E1M8bihsmp9GEBEdLCDCwhrIpFX7xuxfudYH9MLRKAdKwJ8xqrpFjgFFbosvKH" +
	"oqi0gH2RLS7+G8V5wReWTOVKvzy3zD8XlMgtdSUnG+MiP0aaa8jFGfprFoeMMJJr" +
	"5cO89UjjC+qYkcqA9HP7mf2VmenEJSJt7E0651CE3/eaEONgoIDudTXZt8CB4vvb" +
	"OnL8QfmVp2kzKKl1hsN43jPVvRqbM6+4OR1Yp3T1UVKLcGwpZCh3t/fYgpyjBqrQ" +
	"qEWQzhKs+bTWlCeDpXdxhHJIquHhzZ8Sm2s/r1GDv7kVLw9d8APyWep5WrFVE/r7" +
	"kN9Ac8tbiqTM54sFMTQLkzhPTIhNdjIQkn8i0H2673cGYkFYWLIO+I8jFhMl3ZBw" +
	"Qt54Wnb35zInpchoQjCCAQIGCSqGSIb3DQEHAaCB9ASB8TCB7jCB6wYLKoZIhvcN" +
	"AQwKAQKggbQwgbEwHAYKKoZIhvcNAQwBAzAOBAhlMkjWb0xXBAICCAAEgZALV1Nz" +
	"LJa6MAAaYkIseJRapR+h9Emzew5dstSbB23kMt3PLyafv4M0AvUi3Mk+VEowmL62" +
	"WhC+PcQfdE4YaW6PvepWjS+gk42RA6hT8zdG2PiP2rhS4wuxs/I/rPQIgY8i3M2R" +
	"GmrR9CcOFCE7hnpJp/0tm7Trc11SfCNB3MXYSvttL5ZJ29ewYZ9kg+lv0XoxJTAj" +
	"BgkqhkiG9w0BCRUxFgQU7q/jH1Mc5Ctiwkdl0Hx9xKSYy90wMTAhMAkGBSsOAwIa" +
	"BQAEFDPX7JM9l8ZnTwGGaDQQvlp7RiBKBAg2WsoFwawSzwICCAA=",
)

func mustBase64Decode(b64 string) []byte {
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, decoder); err != nil {
		panic(err)
	}

	return buf.Bytes()
}
