:orphan:

.. _scion-pki_trc_sign:

scion-pki trc sign
------------------

Sign a TRC

Synopsis
~~~~~~~~


'sign' signs a TRC payload with the signing key and signing certificate.

Voting, proof-of-possession, and root acknowledgement signatures can be added by using the
corresponding signing keys and certificates.

By default, the resulting signed object is written to a file with the following
naming pattern::

	ISD<isd>-B<base_version>-S<serial_number>.<signing-isd_as>-<signature-type>.trc

An alternative name can be specified with the \--out flag.



::

  scion-pki trc sign <payload_file> <crt_file> <key_file> [flags]

Examples
~~~~~~~~

::

    scion-pki trc sign ISD1-B1-S1.pld.der sensitive-voting.crt sensitive-voting.key
    scion-pki trc sign ISD1-B1-S1.pld.der regular-voting.crt regular-voting.key --out ISD1-B1-S1.regular.trc

Options
~~~~~~~

::

  -h, --help             help for sign
  -o, --out string       Output file path. If --out is set, --out-dir is ignored.
      --out-dir string   Output directory. If --out is set, --out-dir is ignored. (default ".")

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI

