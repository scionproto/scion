.. _scion-pki_key_match_certificate:

scion-pki key match certificate
-------------------------------

Find the matching certificate for the key

Synopsis
~~~~~~~~


'certificate' finds all the matching certificates for the key.
If a file contains a certificate chain, only the first certificate in the chain
is considered.

The output contains all certificates that authenticate the key.


::

  scion-pki key match certificate <private-key> <certificate> [<certificate> ...] [flags]

Examples
~~~~~~~~

::

    scion-pki key match certificate cp-as.key ISD1-ASff00_0_110.pem
    scion-pki key match certificate cp-as.key *.pem

Options
~~~~~~~

::

  -h, --help               help for certificate
      --separator string   The separator between file names (default "\n")

SEE ALSO
~~~~~~~~

* `scion-pki key match <scion-pki_key_match.html>`_ 	 - Match the key with other trust objects

