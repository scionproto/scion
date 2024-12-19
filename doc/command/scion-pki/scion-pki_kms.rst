:orphan:

.. _scion-pki_kms:

scion-pki kms
-------------

Run the step-kms-plugin

Synopsis
~~~~~~~~


This command leverages the step-kms-plugin to interact with cloud Key Management
Systems (KMS) and Hardware Security Modules (HSM).

The commands are passed directly to the step-kms-plugin. For more information on
the available commands and their usage, please refer to the step-kms-plugin
documentation at https://github.com/smallstep/step-kms-plugin. In order to enable
KMS support, the step-kms-plugin must be installed and available in the PATH.

Various commands of the scion-pki tool allow the use of KMS. In all cases, the
private key needs to already exist in the KMS. To instruct the scion-pki tool to
use the key in the KMS, the --kms flag must be set.

For more information about supported KMSs and uri pattern, please consult
https://smallstep.com/docs/step-ca/cryptographic-protection.


::

  scion-pki kms [command] [flags]

Options
~~~~~~~

::

  -h, --help   help for kms

SEE ALSO
~~~~~~~~

* :ref:`scion-pki <scion-pki>` 	 - SCION Control Plane PKI Management Tool

