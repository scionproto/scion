:orphan:

.. _scion-pki_trc_extract_payload:

scion-pki trc extract payload
-----------------------------

Extract the TRC payload

Synopsis
~~~~~~~~


'payload' extracts the asn.1 encoded DER TRC payload.

To inspect the created asn.1 file you can use the openssl tool::

 openssl asn1parse -inform DER -i -in payload.der

(for more information see 'man asn1parse')


::

  scion-pki trc extract payload [flags]

Examples
~~~~~~~~

::

    scion-pki trc extract payload -o payload.der input.trc

Options
~~~~~~~

::

      --format string   Output format (der|pem) (default "der")
  -h, --help            help for payload
  -o, --out string      Output file (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc extract <scion-pki_trc_extract>` 	 - Extract parts of a signed TRC

