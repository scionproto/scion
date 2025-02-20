# Configuration file for the Sphinx documentation builder.
#
# See documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import subprocess
import os

# -- Project information -----------------------------------------------------

project = "SCION"
copyright = "2023, Anapaya Systems, ETH Zurich, SCION Association"
author = "Anapaya Systems, ETH Zurich, SCION Association"


# -- General configuration ---------------------------------------------------

# Set canonical URL from the Read the Docs Domain
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "")

# Tell Jinja2 templates the build is running on Read the Docs
html_context = {}
if os.environ.get("READTHEDOCS", "") == "True":
    html_context["READTHEDOCS"] = True

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "recommonmark",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_rtd_theme",
    "sphinx.ext.extlinks",
    "sphinxcontrib.openapi",
    "sphinxcontrib.mermaid",
]

copybutton_prompt_text = r"\w*\$ "  # matches e.g. <hostname>$
copybutton_prompt_is_regexp = True
copybutton_only_copy_prompt_lines = True


# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = [
    "venv",
    "requirements.in",
    "requirements.txt",
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "manuals/*/*",  # manuals/<x>.rst uses "include" directive to compose files from subdirectories
    "dev/design/TEMPLATE.rst",
]

master_doc = "index"

nitpicky = True

option_emphasise_placeholders = True

# -- extlinks definitions for links to github ---

# Determine current git commit for permalinks to files on github.
# Note: somewhat obviously, these links will only work if the current rev has been pushed.
try:
    file_ref_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
except subprocess.CalledProcessError:
    file_ref_commit = "master"  # only used on unexpected problem with executing git

extlinks = {
    # :issue:`123` is an issue link displayed as "#123"
    "issue": ("https://github.com/scionproto/scion/issues/%s", "#%s"),
    # :file-ref:`foo/bar.go` is a link to a file in the repo, displayed as "foo/bar.go"
    "file-ref": (
        "https://github.com/scionproto/scion/blob/" + file_ref_commit + "/%s",
        "%s",
    ),
}

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

html_theme_options = dict(
    style_external_links=True,
)

manpages_url = "https://manpages.debian.org/{path}"


# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = [""]

html_css_files = [
    "css/custom.css",
]

html_js_files = [
    "https://unpkg.com/@alpinejs/persist@3.14.1/dist/cdn.min.js",
    "https://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js",
]
