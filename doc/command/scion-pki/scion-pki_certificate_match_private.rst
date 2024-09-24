:orphan:

.. _scion-pki_certificate_match_private:

scion-pki certificate match private
-----------------------------------

Find the matching private keys for the certificate

Synopsis
~~~~~~~~


'private' finds all the matching private keys for the certificate.
If the file contains a certificate chain, only the keys authenticated by the first
certificate in the chain are considered.

The output contains all the private keys that are authenticated by the certificate.


::

  scion-pki certificate match private <certificate> <private-key> [<private-key> ...] [flags]

Examples
~~~~~~~~

::

    scion-pki certificate match private ISD1-ASff00_0_110.pem cp-as.key
    scion-pki certificate match private ISD1-ASff00_0_110.pem *.key

Options
~~~~~~~

::

  -h, --help               help for private
      --kms string         The uri to configure a Cloud KMS or an HSM.
      --separator string   The separator between file names (default "\n")

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate match <scion-pki_certificate_match>` 	 - Match the certificate with other trust objects

