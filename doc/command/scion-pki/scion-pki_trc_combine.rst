:orphan:

.. _scion-pki_trc_combine:

scion-pki trc combine
---------------------

Combine partially signed TRCs

Synopsis
~~~~~~~~


'combine' combines the signatures on partially signed TRCs into one single TRC.
The command checks that all parts sign the same TRC payload content.

No further checks are made. Check that the TRC is valid and verifiable with the
appropriate commands.


::

  scion-pki trc combine [flags]

Examples
~~~~~~~~

::

    scion-pki trc combine --payload ISD1-B1-S1.pld -o ISD1-B1-S1.trc ISD1-B1-S1.org1 ISD1-B1-S1.org2

Options
~~~~~~~

::

      --format string    Output format (der|pem) (default "der")
  -h, --help             help for combine
  -o, --out string       Output file (required)
  -p, --payload string   The TRC payload. If provided, it will be used as a reference payload to compare the partially signed TRC payloads against. It can be either DER or PEM encoded.

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI

