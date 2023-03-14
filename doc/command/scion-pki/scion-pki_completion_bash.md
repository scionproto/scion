---
orphan: true
---

(app-scion-pki-completion-bash)=

# scion-pki completion bash

Generate the autocompletion script for bash
## Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(scion-pki completion bash)

To load completions for every new session, execute once:
### Linux:

	scion-pki completion bash > /etc/bash_completion.d/scion-pki
### macOS:

	scion-pki completion bash > $(brew --prefix)/etc/bash_completion.d/scion-pki

You will need to start a new shell for this setup to take effect.


```
scion-pki completion bash
```
## Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```
## SEE ALSO

* [scion-pki completion](scion-pki_completion.md)	 - Generate the autocompletion script for the specified shell

