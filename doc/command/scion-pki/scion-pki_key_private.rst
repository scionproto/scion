:orphan:

.. _scion-pki_key_private:

scion-pki key private
---------------------

Generate private key at the specified location

Synopsis
~~~~~~~~


'private' generates a PEM encoded private key at the specified location.

The contents are the private key in PKCS #8 ASN.1 DER format.


::

  scion-pki key private [flags] <private-key-file>

Examples
~~~~~~~~

::

    scion-pki key private cp-as.key
    scion-pki key private --curve P-384 cp-as.key

Options
~~~~~~~

::

      --curve string   The elliptic curve to use (P-256|P-384|P-521) (default "P-256")
      --force          Force overwritting existing private key
  -h, --help           help for private

SEE ALSO
~~~~~~~~

* :ref:`scion-pki key <scion-pki_key>` 	 - Manage private and public keys

