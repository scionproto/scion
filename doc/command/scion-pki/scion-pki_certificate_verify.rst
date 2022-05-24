.. _scion-pki_certificate_verify:

scion-pki certificate verify
----------------------------

Verify a certificate chain

Synopsis
~~~~~~~~


'verify' verifies the certificate chains based on a trusted TRC.

The chain must be a PEM bundle with the AS certificate first, and the CA
certificate second.

The ISD-AS property of the subject identified by the certificate
(or in the case of a certificate chain, the leaf certificate)
can be validated by specifying the \--subject-isd-as flag and
the expected ISD-AS value.


::

  scion-pki certificate verify [flags]

Examples
~~~~~~~~

::

    scion-pki certificate verify --trc ISD1-B1-S1.trc,ISD1-B1-S2.trc ISD1-ASff00_0_110.pem
    scion-pki certificate verify --trc ISD1-*.trc ISD1-ASff00_0_110.pem

Options
~~~~~~~

::

      --currenttime int         Optional unix timestamp that sets the current time
  -h, --help                    help for verify
      --subject-isd-as string   ISD-AS property of the subject of the certificate
      --trc strings             Comma-separated list of trusted TRC files or glob patterns. If more than two TRCs are specified,
                                 only up to two active TRCs with the highest Base version are used (required)

SEE ALSO
~~~~~~~~

* `scion-pki certificate <scion-pki_certificate.html>`_ 	 - Manage certificates for the SCION control plane PKI.
* `scion-pki certificate verify ca <scion-pki_certificate_verify_ca.html>`_ 	 - Verify a CA certificate

