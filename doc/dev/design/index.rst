****************
Design Documents
****************

Design documents serve as an agreed upon plan for the implementation of
substantial changes and as a record of the design choices made.
See section :ref:`change-proposal-process` for the overview on the overall
contribution process.

- **Creation**:
  Design documents are created from the template :file-ref:`doc/dev/design/TEMPLATE.rst`.
  While the design is still being discussed, it is in status **WIP** and linked in the
  section :ref:`design-docs-wip`. The document can be merged in this state as soon as the
  proposal is accepted, even if it still needs more work.

  Once discussion on the design converges and the design document is finalized, its status
  becomes one of **Active**, **Postponed**, or **Rejected** and it is inserted to the corresponding
  section.

- **Implementation**:
  Together with the implementation of the change, user manuals and any other
  documentation are updated.

  The design document is only updated if amendments to the described design are
  found to be necessary during this phase.
- **Completion and Freeze**:
  Once all parts of the implementation are completed, the design document is
  marked as **Completed** and linked to section :ref:`design-docs-completed`.

  After this point, the design document is frozen as historical record and no
  longer updated. Later substantial changes undergo the entire process again,
  creating new design documents where appropriate.

  During implementation the design may also become suspended (**Postponed**)
  or abandoned (**Rejected** or **Outdated**).

- **Replacement**:
  If the implementation has changed so much that a design document is no longer
  a useful reference for the current system, it's status is changed to **Outdated**
  and it is linked to section :ref:`design-docs-outdated`.

.. _design-docs-wip:

WIP
===
.. toctree::
   :maxdepth: 1

   NAT-address-discovery

.. _design-docs-postponed:

Postponed
=========
.. toctree::
   :maxdepth: 1

   scmp-authentication

.. _design-docs-active:

Active
======
.. toctree::
   :maxdepth: 1

   uri
   grpc
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
   BorderRouter

.. _design-docs-outdated:

Outdated
========
.. toctree::
   :maxdepth: 1

   BeaconService
   PathService
   forwarding-key-rollover
   ColibriService

.. _design-docs-rejected:

Rejected
========
.. toctree::
   :maxdepth: 1

.. seealso::

   :ref:`change-proposal-process`
      Documentation of the overall :ref:`change-proposal-process`.

   :ref:`governance`
      The :ref:`governance model <governance>` describes who ultimately approves or rejects change proposals and design documents.
