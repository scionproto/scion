****************
Design Documents
****************

Design documents serve as an agreed upon plan for the implementation of
substantial changes and as a record of the design choices made.
See section :ref:`change-proposal-process` for the overview on the overall
contribution process.

- **Creation**:
  Design documents are created from the template :file-ref:`doc/dev/design/TEMPLATE.rst`.

  Once discussion on a change proposal converges and a design document is
  approved, it is inserted to section :ref:`design-docs-active`.
- **Implementation**:
  Together with the implementation of the change, user manuals and any other
  documentation are updated.

  The design document is only updated if amendments to the described design are
  found to be necessary during this phase.
- **Completion and Freeze**:
  Once all parts of the implementation are completed, the design document is
  marked as complete and the document moves to the section :ref:`design-docs-completed`.

  After this point, the design document is frozen as historical record and no
  longer updated. Later substantial changes undergo the entire process again,
  creating new design documents where appropriate.
- **Replacement**:
  If the implementation has changed so much that a design document is no longer
  a useful reference for the current system, it moves to section :ref:`design-docs-outdated`.


.. _design-docs-active:

Active
======
.. toctree::
   :maxdepth: 1

   uri
   grpc
   BorderRouter
   router-perf-model
   router-port-dispatch

.. _design-docs-completed:

Completed
=========
.. toctree::
   :maxdepth: 1

   EPIC
   PathPolicy
   endhost-bootstrap

.. _design-docs-outdated:

Outdated
========
.. toctree::
   :maxdepth: 1

   BeaconService
   PathService
   forwarding-key-rollover
   ColibriService


.. seealso::

   :ref:`change-proposal-process`
      Documentation of the overall :ref:`change-proposal-process`.

   :ref:`governance`
      The :ref:`governance model <governance>` describes who ultimately approves or rejects change proposals and design documents.
