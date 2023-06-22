:orphan:

.. _scion-pki_certificate_verify_ca:

scion-pki certificate verify ca
-------------------------------

Verify a CA certificate

Synopsis
~~~~~~~~


'ca' verifies the CA certificate based on a trusted TRC.

The CA certificate must be a PEM encoded.


::

  scion-pki certificate verify ca [flags]

Examples
~~~~~~~~

::

    scion-pki certificate verify --trc ISD1-B1-S1.trc ISD1-ASff00_0_110.ca.crt

Options
~~~~~~~

::

      --currenttime int   Optional unix timestamp that sets the current time
  -h, --help              help for ca
      --trc string        trusted TRC (required)

SEE ALSO
~~~~~~~~

* :ref:`scion-pki certificate verify <scion-pki_certificate_verify>` 	 - Verify a certificate chain

