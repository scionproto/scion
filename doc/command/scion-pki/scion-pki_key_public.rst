:orphan:

.. _scion-pki_key_public:

scion-pki key public
--------------------

Generate public key for the provided private key

Synopsis
~~~~~~~~


'public' generates a PEM encoded public key.

By default, the public key is written to standard out.


::

  scion-pki key public [flags] <private-key-file>

Examples
~~~~~~~~

::

    scion-pki key public cp-as.key
    scion-pki key public cp-as.key --out cp-as.pub

Options
~~~~~~~

::

      --force        Force overwritting existing public key
  -h, --help         help for public
      --out string   Path to write public key

SEE ALSO
~~~~~~~~

* :ref:`scion-pki key <scion-pki_key>` 	 - Manage private and public keys

