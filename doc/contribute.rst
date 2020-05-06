.. _contribution-guide:

***********************************
Contributing to the SCION code base
***********************************

Welcome to the SCION contribution guide! If you are interested in contributing to
the project, this page will help you out on your journey to your first SCION commit.

Before starting out, just one thing: if you have any questions, you can always
find us on our `Slack workspace <https://scionproto.slack.com>`__ or on our
`Github project page <https://github.com/scionproto/scion>`__. Do not hesitate to
ask us anything, or feel free to just drop by and say "Hi".

.. note:: Note for Anapayans

   This section contains general rules about how to contribute to the
   open-source SCION project. If you are an Anapaya employee, some additional
   rules may apply. Please see the internal Contribution Guide for more
   information.

What skills do you need to contribute?
======================================

SCION is a complex project, and uses a lot of different technologies. If you are unfamiliar
with some of them, we have compiled a list containing some great resources to get you started.

+----------------+----------------------------+------------------------------------------+
|     Language   |    Contribution area       |    Tutorials                             |
+----------------+----------------------------+------------------------------------------+
|       Go       |   SCION Control-plane      |    :ref:`resources-for-learning-go`      |
|                |   SCION Data-plane         |                                          |
|                |   SCION Tools              |                                          |
+----------------+----------------------------+------------------------------------------+
|   Python       |   Acceptance testing       | Coming soon                              |
|                |   Helper scripts           |                                          |
+----------------+----------------------------+------------------------------------------+
|  Starlark      |   Bazel build/test system  | Coming soon                              |
+----------------+----------------------------+------------------------------------------+

Contributing to the Python and Starlark code bases is a bit trickier, so if you're just now
starting out, we recommend going for Go first.

You might also see some Bash and Makefile code in the code base. While this code changes from
time to time, we strongly discourage contributions to these areas. Code in these languages also
has a high chance of getting deleted completely in a refactoring pass.

For version control, we use Git and GitHub. For more information about using Git (including
links to resources to get you started if you've never used before), please visit :ref:`how-to-use-git-and-github`.

No matter what language you want to contribute to, one of the first steps to take is to set
up a development environment. See :ref:`setting-up-the-development-environment` for the needed steps.
If you encounter issues, please visit `Slack <https://scionproto.slack.com>`__ and ask for help.

Finding an issue to contribute to
=================================

We use GitHub labels to categorize issues in the SCION tracker. The two most interesting categories
when searching for something to contribute to are:

- `Help wanted issues <https://github.com/scionproto/scion/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22>`__.
  These are issues that nobody is working on at the moment, and are up for grabs.
- `Good first issue issues <https://github.com/scionproto/scion/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22>`__.
  These are usually **Help wanted** uses that are somewhat simpler. These are a good place to start if you've
  never contributed to the project before.

Once you find something you like, post a comment on the issue announcing that
you're interested in working on it. This initial message signals to others that
somebody is already working on it (and thus avoids duplicate work), and also is
the first step in gathering more information about the issue from the SCION team.

From this point on, somebody from the SCION maintainers team will reach out to
you and guide you for the rest of the process. If you have any questions, please
remember to shoot us a question on our `Slack <https://scionproto.slack.com>`__.

Finally, make sure that the code you write adheres to the SCION project
:ref:`language-style-guides`.

Learning resources
==================

.. toctree::
   :maxdepth: 1

   contribute/go-learn.rst
   contribute/git.rst

.. _language-style-guides:

Language style guides
=====================

.. toctree::
   :maxdepth: 1

   contribute/bazel-style
   contribute/go-style
   contribute/json-style
   contribute/python-style
   contribute/rst-style
   contribute/toml-style
