:orphan:

.. _scion-pki_completion_powershell:

scion-pki completion powershell
-------------------------------

Generate the autocompletion script for powershell

Synopsis
~~~~~~~~


Generate the autocompletion script for powershell.

To load completions in your current shell session:

	scion-pki completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


::

  scion-pki completion powershell [flags]

Options
~~~~~~~

::

  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions

SEE ALSO
~~~~~~~~

* :ref:`scion-pki completion <scion-pki_completion>` 	 - Generate the autocompletion script for the specified shell

