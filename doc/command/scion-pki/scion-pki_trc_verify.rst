:orphan:

.. _scion-pki_trc_verify:

scion-pki trc verify
--------------------

Verify a TRC chain

Synopsis
~~~~~~~~


'verify' verifies a TRC chain based on a trusted anchor point.

The anchor can either be a collection of trusted certificates bundled in a PEM
file, or a trusted TRC. TRC update chains that start with a base TRC can be
verified with either type of anchor. TRC update chains that start with a
non-base TRC must have a TRC as anchor.
With the optional flag --isd, the ID of the ISD for which the TRC claims to be
the root of trust can be matched against an expected value.


::

  scion-pki trc verify [flags]

Examples
~~~~~~~~

::

    scion-pki trc verify --anchor bundle.pem ISD1-B1-S1.trc
    scion-pki trc verify --anchor ISD1-B1-S1.trc ISD1-B1-S2.trc ISD1-B1-S3.trc

Options
~~~~~~~

::

  -a, --anchor string   trust anchor (required)
  -h, --help            help for verify
      --isd uint16      ISD identifier

SEE ALSO
~~~~~~~~

* :ref:`scion-pki trc <scion-pki_trc>` 	 - Manage TRCs for the SCION control plane PKI

