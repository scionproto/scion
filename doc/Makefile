# This Makefile helps to build the sphinx documentation.
# This runs tools using python dependencies managed via bazel/rules_python for the convenience of contributors
# that have already set up bazel.
# Alternatively, with dependencies from ./requirements.txt installed with pip, e.g. in a venv,
# this Makefile can be used directly invoking the build tool (e.g "make SPHINX_BUILD=sphinx-build")
#
# Note that for builds on the readthedocs infrastructure, this Makefile or bazel is not used!
# See ../.readthedocs.yaml

# Variables can be overridden from the command line from the environment.
SPHINX_BUILD	 ?= bazel run //doc:sphinx-build --
SPHINX_AUTOBUILD ?= bazel run //doc:sphinx-autobuild --
SPHINXOPTS    ?= -W --keep-going # treat warnings as errors, but process all files when an error occurs
SOURCEDIR     = $(abspath .)
BUILDDIR      = $(abspath ./_build)
HOST 		 ?= localhost

# Build docs with Sphinx using the "make mode" option.
# Explicitly list the main build targets so they auto-complete in shells.
# The first listed name is the default goal (i.e. `make` is `make html`).
.PHONY: html latex latexpdf linkcheck help
html latex latexpdf linkcheck help:
	$(SPHINX_BUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

# Catch-all pattern to match any unknown target, too.
.PHONY: %
%:
	$(SPHINX_BUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS)

# Autobuild; automatically build HTML on source changes and serve on localhost
# Note: most options are forwarded as-is to sphinx, but --keep-going is not understood and we explicitly drop it.
.PHONY: autobuild
autobuild:
	$(SPHINX_AUTOBUILD) "--host=$(HOST)" "$(SOURCEDIR)" "$(BUILDDIR)"  $(filter-out --keep-going,$(SPHINXOPTS)) 

.PHONY: clean
clean:
	rm -rf _build
