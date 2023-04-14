SCION: a next-generation inter-domain routing architecture
==========================================================

SCION (Scalability, Control, and Isolation On Next-generation networks) is a
secure and reliable inter-domain routing protocol, designed to provide route
control, failure isolation, and explicit trust information for end-to-end
communication.

.. (Comment)
   This documentation is structured into sections with different purposes/audiences

   - SCION:
     Explanations and Specifications. Explain SCION on a conceptual level.
     Should introduce concepts that a user or dev needs to make sense of the manuals etc.

     Target audience: anyone (users, developers, outsiders)

   - Reference manuals:
     Target audience: users of this SCION implementation (operator of SCION
     infrastructure or hosts), users of any of the SCION APIs.

   - Developer section:
     Target audience: contributors to this SCION implementation

Overview
^^^^^^^^

This section explains the ideas and concepts of SCION.

.. toctree::
   :maxdepth: 1
   :caption: SCION
   :hidden:

   Protocols <protocols/index>
   Cryptography <cryptography/index>
   hidden-paths
   beacon-metadata
   glossary

* **Overview (TODO)**: |
  SCION |
  SCION Control Plane |
  SCION Data Plane |
  SCION End Hosts

* **Specifications**:
  :doc:`protocols/index` |
  :doc:`cryptography/index`

* **Advanced features**:
  :doc:`hidden-paths` |
  :doc:`beacon-metadata`

Reference Manuals
^^^^^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 1
   :caption: Reference Manuals
   :hidden:

   manuals/router
   manuals/dispatcher
   manuals/daemon
   manuals/control
   manuals/gateway
   manuals/common

   command/scion/scion
   command/scion-pki/scion-pki

   snet API <https://pkg.go.dev/github.com/scionproto/scion/pkg/snet>

* **For operators of a SCION end host**:
  :doc:`command/scion/scion` |
  :doc:`manuals/daemon` |
  :doc:`manuals/dispatcher`

* **For operators of a SCION AS**:
  :doc:`manuals/router` |
  :doc:`manuals/control` |
  :doc:`manuals/gateway` |
  :doc:`manuals/common` |
  :doc:`command/scion-pki/scion-pki`

* **For developers of SCION applications**:
  `snet API <https://pkg.go.dev/github.com/scionproto/scion/pkg/snet>`_

.. TODO
   snet documentation should be a good starting point for using SCION as an application library.
   For this, the package documentation needs to be streamlined a bit...

Developer Documentation
^^^^^^^^^^^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 1
   :caption: Developer Documentation
   :hidden:

   dev/contribute
   dev/setup
   dev/run
   dev/style/index
   dev/testing/index
   dev/dependencies
   dev/design/index

Start with the :doc:`dev/contribute` you want to contribute to this SCION implementation

* **Policies and Processes**:
  :ref:`governance` |
  :ref:`change-proposal-process` |
  :doc:`dev/style/index`

* **Building and running**
  :doc:`dev/setup` |
  :doc:`dev/run` |
  :doc:`dev/dependencies` |
  :doc:`dev/testing/index`

* **Design Documents**:
  :doc:`dev/design/index`
