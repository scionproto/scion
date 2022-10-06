.. _scion-pki_certificate_fingerprint:

scion-pki certificate fingerprint
---------------------------------

Calculate the SHA256 fingerprint of a certificate or certificate chain

Synopsis
~~~~~~~~


'fingerprint' computes the SHA256 fingerprint of the raw certificate or
certificate chain.

If 'cert-file' contains a single certificate, the SHA256 is computed over the raw
DER encoding. If it contains a certificate chain, the SHA256 is computed over the
concatenation of the raw DER encoding of the certificates in order of appearance.

If the flag \--format is set to "emoji", the format of the output is a string of emojis

::

  scion-pki certificate fingerprint [flags] <cert-file>

Examples
~~~~~~~~

::

    scion-pki certificate fingerprint ISD1-ASff00_0_110.pem
    scion-pki certificate fingerprint --format emoji ISD1-ASff00_0_110.pem
    scion-pki certificate fingerprint --format hex ISD1-ASff00_0_110.pem
  		

Options
~~~~~~~

::

      --format string   The format of the fingerprint (hex|base64|base64-url|base64-raw|base64-url-raw|emoji). (default "hex")
  -h, --help            help for fingerprint

SEE ALSO
~~~~~~~~

* `scion-pki certificate <scion-pki_certificate.html>`_ 	 - Manage certificates for the SCION control plane PKI.

