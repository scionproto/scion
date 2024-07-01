:orphan:

.. _scion-pki_completion_zsh:

scion-pki completion zsh
------------------------

Generate the autocompletion script for zsh

Synopsis
~~~~~~~~


Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(scion-pki completion zsh)

To load completions for every new session, execute once:

#### Linux:

	scion-pki completion zsh > "${fpath[1]}/_scion-pki"

#### macOS:

	scion-pki completion zsh > $(brew --prefix)/share/zsh/site-functions/_scion-pki

You will need to start a new shell for this setup to take effect.


::

  scion-pki completion zsh [flags]

Options
~~~~~~~

::

  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions

SEE ALSO
~~~~~~~~

* :ref:`scion-pki completion <scion-pki_completion>` 	 - Generate the autocompletion script for the specified shell

