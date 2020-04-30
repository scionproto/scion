.. _contribution-guide:

******************
Contribution Guide
******************

This section contains general rules about how to contribute to the SCION repo.
If you are an Anapaya employee, some additional rules apply. Please see the
internal Contribution Guide for more information.

How to use Git and Github
=========================

Setting up github auth
----------------------

Interacting with github using git will require you to authenticate every time.
In order to make your life easier, we strongly suggest setting up automated
authentication using an ssh-key. Github has a nice `doc on how to set it
up <https://help.github.com/articles/generating-ssh-keys/>`__.

Forking the repository
----------------------

The first step is to make your own personal fork of the main repository. You can
do this by going to the `SCION repo <https://github.com/scionproto/scion/>`__, and
clicking the 'Fork' button on the top right, and then choosing your own personal
repository.

This gives you a complete copy of the main scion repo, in which are you free to
make changes without affecting anyone else. The only downside to this is that
you have a little extra work to do to keep it up to date with the main repo.
This is covered below.

Cloning the repository
----------------------

Now that you have your own fork, follow the steps in the
`README <https://github.com/scionproto/scion/blob/master/README.md>`__ to set up
your workspace. When you get to the point of cloning the repository, use the
directory the README indicates, but clone your own fork into it instead:

.. code-block:: bash

  cd "<workspace>"
  git clone git@github.com:<username>/scion

(If you have authentication setup correctly, you won't be prompted for a password.)

This will initialize a git repository on your local machine and pull everything
from your forked personal repository in there.

Keeping your personal fork up to date
-------------------------------------

In order to keep your personal fork in sync with the main repository, you need
to add the main repo as new remote repo in your local clone. Github's `guide
for this <https://help.github.com/articles/configuring-a-remote-for-a-fork/>`__ is
pretty straightforward, but can be summarised as:

.. code-block:: bash

    git remote add upstream git@github.com:scionproto/scion.git

Now that you have this setup, the `procedure for doing the
sync <https://help.github.com/articles/syncing-a-fork/>`__ is pretty
straight-forward:

1. Fetch the changes from the main repo: ``git fetch upstream``
1. Switch to your master branch: ``git checkout master``
1. Merge the upstream changes into your main branch: ``git merge --ff-only upstream/master``
1. Push the changes to your github fork: ``git push``

A simple script to automate this can be found in the repo under
``/scripts/mastersync.sh``.

Basic Git/Github Workflow
-------------------------

Git has many powerful features, but the one you will probably use most are
branches. You can think of branches as a different version of your project,
however, they are much more lightweight than their SVN counterparts and
therefore heavily used in your everyday workflow.

The main (default) branch is usually called _master_ and that is also the one
currently active when you first clone the repository. The master branch holds
the current snapshot of the project and should never be directly used for
development. For each new feature or bugfix you create a new branch based on the
current master branch, implement your changes, review them, commit them and in
the end merge them back to the master branch.

Example
^^^^^^^

Let's go through a simple example to illustrate this.

First we create a new branch called 'bufferOverflowFix'.

.. code-block:: bash

    git branch bufferOverflowFix

This will create a new branch with the given name based on the current master
branch. The next step is to 'checkout' this branch, since we are still on the
master branch:

.. code-block:: bash

    git checkout bufferOverflowFix

These two steps can also be combined with:

.. code-block:: bash

    git checkout -b bufferOverflowFix

Now we can edit any files we want without touching the code in the master
branch. You can see the files changed with ``git status`` and ``git diff <file
name>`` will show what exactly has changed since the last commit.

When we are done editing files, we have to commit the changes to the (local)
repository.

.. code-block:: bash

    git commit -am "Some meaningful comment about the changes."

Note, so far the new branch we created exists only in the local repository. The
remote repository doesn't know anything about it yet. To push it to the remote
repository we use

.. code-block:: bash

    git push -u origin bufferOverflowFix

*origin* is your fork of the main repository.

Good commit messages
--------------------

We adhere to the rules in the `Go Contribution
Guide <https://golang.org/doc/contribute.html#commit_messages>`__.

Similarly to the contribution guide above, the first commit line should complete
the sentence "This change modifies SCION to ...". This means it should start
with a lower-case letter, and should not be a complete sentence.

Do not use full URLs to reference issues, they are needlessly verbose. To
reference an issue in the current repository, use the #12345 notation. To
reference an issue in a different repository, use the Github fully-qualified
syntax (e.g., scionproto/scion#12345).

Pull Requests
-------------

Pull Requests are a powerful tool provided by github mainly to review code
before it is merged to the main branch.

In order to create a pull request you need to push your branch containing the
new code to the github repository (as explained above). This new branch will now
show up in the web interface (under 'branches' on the main repository page).
From there you can click on 'New pull request' where you can add a description
and check what's included in the pull request.

You can then assign the pull request to one or more reviewers, which will get
notified to do a code review.

Code reviews
------------

Github's code review interface is fairly basic, and is missing some key
features. To compensate for this, we're using an external review system,
[reviewable.io](reviewable.io). This integrates into the github PR, and keeps
track of comments that have been addressed or not. When all issues pointed out
by your reviewer are fixed, your code is probably ready to be merged.

Best practices
--------------

- Keep your development branch(es) rebased on master.
- Squash your contribution to a single commit before sending a PR.
- Incremental updates to a PR should be separate commits, as this allows
  reviewers to see what has changed.
- Each PR should be self-contained (as much as possible), have a description
  that covers all the changes in it, and always leave the tree in a working
  state.
- If you have any git problems, ping someone on the slack channel for help.
  Don't suffer alone :)

Final comments
--------------

Git is a very powerful tool and this tutorial barely scratches the surface. It
just presents the most common use case, but it should get you started. Please
use the vast amount of really good git and `github resources on the
web  <http://git-scm.com/book>`__.

Go style guide
==============

Unless specified otherwise below, stick to golang's
`CodeReviewComments <https://github.com/golang/go/wiki/CodeReviewComments>`__.

Generally the code should be formatted with ``gofmt`` (checked by CI).

Lines must be at most 100 characters long (checked by CI via `lll`).

Naming
------

We use mixedCaps notation as recommended by `Effective Go
<https://golang.org/doc/effective_go.html>`__. The following rules apply (note
that a significant part of the code base uses other notations; these should be
refactored, however):

- Use ``sd`` or ``SD`` to refer to the SCION Daemon, not ``Sciond`` or ``SCIOND``.
- Use ``IfID`` or ``ifID`` for SCION Interface Identifiers, not ``IFID`` or ``InterfaceID``.
- Use ``Svc`` or ``svc`` for SCION Service Addresses, not ``SVC`` or ``Service``.
- Use ``TRC`` or ``trc`` for Trust Root Configurations, not ``Trc``.

Imports (checked by CI)
-----------------------

Imports are grouped (separated by empty line) in the following order:

* standard lib
* third-party packages
* our packages

Within each group the imports are alphabetically sorted.

Function declaration over multiple lines
----------------------------------------

If a function declaration uses more than 1 line the first line should be empty:

.. code-block:: go

    func usingMultipleLines(
        args string) error {

        // start the code here
    }

Abbreviations
-------------

For variable names common abbreviations should be preferred to full names, if
they are clear from the context, or used across the codebase.

Examples:

- ``Seg`` instead of ``Segment``
- ``Msger`` instead of ``Messenger``
- ``Sync`` instead of ``Synchronization``

Specialities
------------

goroutines should always call ``defer log.HandlePanic()`` as the first statement (checked by CI).

Logging
-------

* Use the SCION logging, i.e. import ``"github.com/scionproto/scion/go/lib/log"``.
* Do not use ``log.Root().New(...)``, instead use New directly: ``log.New(...)``.
* Keys should be snake case; use ``log.Debug("msg", "some_key", "foo")`` instead
  of ``log.Debug("msg", "someKey", "foo")`` or other variants.
* Try to not repeat key-value pairs in logging calls that are close-by; derive a
  new logging context instead (e.g., if multiple logging calls refer to a
  ``"request"`` for ``"Foo"``, create a sublogger with this context by calling
  ``newLogger = parentLogger.New("request", "Foo")`` and then use
  ``newLogger.Debug("x")``).
* If multiple logging lines need to be correlated for debugging, consider adding
  a debugging ID to them via ``log.NewDebugID``. Usually this is done together
  with the sub-logger pattern in the previous bullet.
* An empty ``log.New()`` has no impact and should be omitted.

Metrics
-------

For metrics implementation, see
`here <https://github.com/scionproto/scion/blob/master/doc/Metrics.md>`__.

Python style guide
==================

We follow the `Google Style Guide for Python <https://google.github.io/styleguide/pyguide.html>`__.

JSON style guide
================

Property names must be ASCII snake_case.

Bazel style guide
=================

Bazel code must follow the official rules as defined in `the Bazel project
<https://docs.bazel.build/versions/master/skylark/build-style.html>`__.

TOML style guide
================

Keys must be ASCII snake_case.

reStructured Text style guide
=============================

reStructured Text allows for quite a bit of freedom in how the markup is
written. In the interest of consistency, please follow the rules below for SCION
documentation.

General
-------

There is no maximum line length, but if possible try to wrap at 80 characters.
Prefer readability over strict wrapping.

Images
------

Images should live either in the same folder as the file that embeds them, or
in a ``fig`` folder. Note that images can be referenced by any documentation file
in the code base, so be careful when moving them, as we do not have an automatic
way of detecting this yet.

If possible (e.g., for DrawIO graphics), vector images should have a ``.txt``
file alongside them with the same name. The file should contain a link to the
source of the vector image.

Headings
--------

Use the following heading styles:

.. code-block:: rest

   ********************
   Page title (chapter)
   ********************

   Level 1 (section)
   =================

   Level 2 (subsection)
   --------------------

   Level 3 (subsubsection)
   ^^^^^^^^^^^^^^^^^^^^^^^

   Level 4 (paragraph)
   """""""""""""""""""

Including code
--------------

Code should be included from a source file using ``literalinclude``
whenever possible. This ensures that there is a single source of truth and
the documentation does not get out of sync easily.

We use guard comments around the code that we want to include. This has two
benefits: It is obvious what code is included in documentation and line number
changes do not matter.

The start is indicated by ``LITERALINCLUDE X START`` and the end by
``LITERALINCLUDE X END``, where ``X`` is replaced by a string that identifies
the guarded block uniquely. When guarding the code of a function, the function
name is a good value for ``X``.

Example file ``digest.sh``

.. code-block:: bash

   display_digest() {
   # LITERALINCLUDE display_digest START
       sha512sum */*.crt
   # LITERALINCLUDE display_digest END
   }

The directive to include the code is

.. code-block:: rest

  .. literalinclude:: digest.sh
     :start-after: LITERALINCLUDE display_digest START
     :end-before: LITERALINCLUDE display_digest END
     :dedent: 4

Whitespace
----------

This section uses the ``!`` character to represent whitespace. This make it easier to separate it
from the RST code blocks in this document.

Indenting list contents
^^^^^^^^^^^^^^^^^^^^^^^

If blocks in a list item require indenting, add it to the base indentantion required by list syntax.
For example, to embed a code block, write:

.. code-block:: rest

   - item
   - item

   !!.. code-block:: go

   !!!!!func Foo() {
   !!!!!     fmt.Println("foo")
   !!!!!}

   - item

and:

.. code-block:: rest

   #. item
   #. really long item that
   !!!wraps around and includes code

   !!!.. code-block:: go

   !!!!!!func Foo() {
             fmt.Println("foo")
   !!!!!!}

   !!!runoff item text, maybe
   #. item

Indenting code
^^^^^^^^^^^^^^

For an explicit code block, indent to the start of the ``code-block`` directive:

.. code-block:: rest

   .. code-block:: go

   !!!func Foo() {
   !!!    fmt.Println("foo")
   !!!}

For a short-hand code block, indent by 4 characters (if this appears in a list, indent by
4 characters in addition to the base list indentation):

.. code-block:: rest

   Text that introduces code::

   !!!!func Foo() {
   !!!!    fmt.Println("foo")
   !!!!}

Indenting Directives
^^^^^^^^^^^^^^^^^^^^

Indent to the start of the directive name (so 3 characters):

.. code-block:: rest

   .. Tip::
   !!!tip text


Directives
----------

Syntax highlighting
^^^^^^^^^^^^^^^^^^^

Use a document-level highlight command if most of the code blocks are written
in the same language:

.. code-block:: rest

   ..highlight:: go

Prefer the short-hand version of adding a code block whenever possible:

.. code-block:: rest

   This is the next block::

       func Foo(x int) {
           fmt.Println("foo")
       }

Admonitions
^^^^^^^^^^^

We use the Read the Docs theme to display documentation, so Admonitions (Hint
blocks, Warnings, Errors, etc.) are supported. See `here
<https://sphinx-rtd-theme.readthedocs.io/en/stable/demo/demo.html#admonitions>`__
for documentation about how to use them.
