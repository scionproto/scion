:orphan:

.. _scion-pki_key_fingerprint:

scion-pki key fingerprint
-------------------------

Computes the fingerprint of the provided key

Synopsis
~~~~~~~~


'fingerprint' computes the fingerprint of the provided key.

The fingerprint of a private key will be based on the public part of the key. For certificates or
certificate chains the fingerprint is computed on the public key of the first certificate
in the file.

By default the fingerprint calculated is SHA-1 hash of the marshaled public key as defined in
https://tools.ietf.org/html/rfc5280#section-4.2.1.2 (1). With the '--full-key-digest' flag, 
the computed fingerprint is the SHA-1 hash with ASN.1 DER-encoded subjectPublicKey.

The subject key ID is written to standard out.


::

  scion-pki key fingerprint [flags] <key-file>

Examples
~~~~~~~~

::

    scion-pki key fingerprint cp-as.key --format base64
    scion-pki key fingerprint ISD1-ASff00_-_110.pem --full-key-digest

Options
~~~~~~~

::

      --format string     The format of the fingerprint (hex|base64|base64-url|base64-raw|base64-url-raw|emoji). (default "emoji")
      --full-key-digest   Calculate the SHA1 sum of the marshaled public key
  -h, --help              help for fingerprint

SEE ALSO
~~~~~~~~

* :ref:`scion-pki key <scion-pki_key>` 	 - Manage private and public keys

