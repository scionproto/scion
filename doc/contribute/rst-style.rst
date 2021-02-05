.. _rst-style-guide:

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

If blocks in a list item require indenting, add it to the base indentation required by list syntax.
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
