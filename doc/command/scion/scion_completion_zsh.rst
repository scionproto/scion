.. _scion_completion_zsh:

scion completion zsh
--------------------

Generate the autocompletion script for zsh

Synopsis
~~~~~~~~


Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions for every new session, execute once:

#### Linux:

	scion completion zsh > "${fpath[1]}/_scion"

#### macOS:

	scion completion zsh > /usr/local/share/zsh/site-functions/_scion

You will need to start a new shell for this setup to take effect.


::

  scion completion zsh [flags]

Options
~~~~~~~

::

  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions

SEE ALSO
~~~~~~~~

* `scion completion <scion_completion.html>`_ 	 - Generate the autocompletion script for the specified shell

