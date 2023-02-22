:orphan:

.. _scion-pki_key_symmetric:

scion-pki key symmetric
-----------------------

Generate symmetric key at the specified location

Synopsis
~~~~~~~~


'symmetric' generates a symmetric key at the specified location.

The content is the symmetrics key in the specified format (base64 or pem with SYMMETRIC KEY block).


::

  scion-pki key symmetric [flags] <symmetric-key-file>

Examples
~~~~~~~~

::

    scion-pki key symmetric master-0.key
    scion-pki key symmetric --format base64 --size 512 master-0.key

Options
~~~~~~~

::

      --force           Force overwritting existing symmetric key
      --format string   The output format (pem|base64) (default "pem")
  -h, --help            help for symmetric
      --size int        The number of bits in the symmetric key (default 256)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki key <scion-pki_key>` 	 - Manage private and public keys

