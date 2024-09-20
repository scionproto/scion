:orphan:

.. _scion-pki_trc_payload:

scion-pki trc payload
---------------------

Generate new TRC payload

Synopsis
~~~~~~~~


'payload' creates the asn.1 encoded der file.

To update an existing TRC the predecessor TRC needs to be specified.

To inspect the created asn.1 file you can use the openssl tool::

 openssl asn1parse -inform DER -i -in payload.der

(for more information see 'man asn1parse')


::

  scion-pki trc payload [flags]

Examples
~~~~~~~~

::

    scion-pki trc payload -t template.toml -o payload.der
    scion-pki trc payload -t template.toml -o payload.der -p predecessor.trc
  		

Options
~~~~~~~

::

      --format string        Output format (der|pem) (default "der")
  -h, --help                 help for payload
  -o, --out string           Output file (required)
  -p, --predecessor string   Predecessor TRC
  -t, --template string      Template file (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI
* :ref:`scion-pki trc payload dummy <scion-pki_trc_payload_dummy>` 	 - Generate dummy TRC payload

