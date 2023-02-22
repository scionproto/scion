# These variables can be overridden from the command line from the environment.
SPHINXOPTS    ?=
SOURCEDIR     = .
BUILDDIR      = _build

# Build docs with Sphinx using the "make mode" option.
# Explicitly list the main build targets so they auto-complete in shells.
# The first listed name is the default goal (i.e. `make` is `make html`).
.PHONY: html latex latexpdf linkcheck help
html latex latexpdf linkcheck help:
	sphinx-build -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

# Catch-all pattern to match any unknown target, too.
.PHONY: %
%:
	sphinx-build -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

# Autobuild; automatically build HTML on source changes and serve on localhost
.PHONY: autobuild
autobuild:
	sphinx-autobuild "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

# Generate commandline docs by building the tools and running their `gendocus` subcommand
.PHONY: command-gendocs
command-gendocs:
	bazel run //doc/command:copy_scion
	bazel run //doc/command:copy_scion-pki
