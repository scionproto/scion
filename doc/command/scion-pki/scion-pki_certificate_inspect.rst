:orphan:

.. _scion-pki_certificate_inspect:

scion-pki certificate inspect
-----------------------------

Inspect a certificate or a certificate signing request

Synopsis
~~~~~~~~


outputs the certificate chain or a certificat signing
request (CSR) in human readable format.

::

  scion-pki certificate inspect [flags] <certificate-file|CSR-file>

Examples
~~~~~~~~

::

    scion-pki certificate inspect ISD1-ASff00_0_110.pem
    scion-pki certificate inspect --short ISD1-ASff00_0_110.pem

Options
~~~~~~~

::

  -h, --help    help for inspect
      --short   Print details of certificate or CSR in short format

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate <scion-pki_certificate>` 	 - Manage certificates for the SCION control plane PKI.

