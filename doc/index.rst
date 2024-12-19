SCION: a next-generation inter-domain routing architecture
==========================================================

SCION (Scalability, Control, and Isolation On Next-generation networks) is a
secure and reliable inter-domain routing protocol, designed to provide route
control, failure isolation, and explicit trust information for end-to-end
communication.

.. (Comment)
   This documentation is structured into sections with different purposes/audiences

   - Technology:
     Explanations and Specifications. Explain SCION on a conceptual level.
     Should introduce concepts that a user or dev needs to make sense of the manuals etc.

     Target audience: anyone (users, developers, outsiders)

   - Reference manuals:
     Target audience: users of **this** SCION implementation (operator of SCION
     infrastructure or hosts), users of any of the SCION APIs.

   - Developer section:
     Target audience: contributors to **this** SCION implementation

Technology
^^^^^^^^^^

The ideas and concepts behind SCION.

.. toctree::
   :maxdepth: 1
   :caption: SCION
   :hidden:

   Overview <overview>
   Control Plane <control-plane>
   Data Plane <data-plane>
   Cryptography <cryptography/index>
   sig
   glossary

* **Overview**:
  :doc:`SCION <overview>` |
  :doc:`Control Plane <control-plane>` |
  :doc:`Data Plane <data-plane>` |
  SCION End Hosts |
  `Applications <https://docs.scion.org/projects/scion-applications/en/latest>`_


Reference Manuals
^^^^^^^^^^^^^^^^^

User documentation for the services, tools and programming libraries of the `open-source SCION
implementation <https://github.com/scionproto/scion>`_.

.. toctree::
   :maxdepth: 1
   :caption: Reference Manuals
   :hidden:

   manuals/install
   manuals/control
   manuals/router
   manuals/gateway
   manuals/daemon
   manuals/dispatcher
   manuals/common

   command/scion/scion
   command/scion-pki/scion-pki

   snet API <https://pkg.go.dev/github.com/scionproto/scion/pkg/snet>
   Applications <https://docs.scion.org/projects/scion-applications/en/latest>

* **For operators of SCION end hosts**:
  :doc:`manuals/install` |
  :doc:`command/scion/scion` |
  :doc:`manuals/daemon` |
  :doc:`manuals/dispatcher`

* **For operators of** :term:`SCION ASes <AS>`:
  :doc:`manuals/install` |
  :doc:`manuals/control` |
  :doc:`manuals/router` |
  :doc:`manuals/gateway` |
  :doc:`manuals/common` |
  :doc:`command/scion-pki/scion-pki`

* **For developers of SCION applications**:
  `snet API <https://pkg.go.dev/github.com/scionproto/scion/pkg/snet>`_

.. TODO
   snet documentation should be a good starting point for using SCION as an application library.
   For this, the package documentation needs to be streamlined a bit...

* **For users of SCION applications**:
  `Applications <https://docs.scion.org/projects/scion-applications/en/latest>`_


Guides and Tutorials
^^^^^^^^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 1
   :caption: Guides and Tutorials
   :hidden:

   tutorials/deploy

* :doc:`tutorials/deploy`: Follow step by step instructions and see what a running SCION network could look like.

Developer Documentation
^^^^^^^^^^^^^^^^^^^^^^^

.. toctree::
   :maxdepth: 1
   :caption: Developer Documentation
   :hidden:

   dev/contribute
   dev/setup
   dev/build
   dev/run
   dev/style/index
   dev/testing/index
   dev/dependencies
   dev/design/index

Start with the :doc:`dev/contribute` to contribute to the open-source SCION implementation.

* **Policies and Processes**:
  :ref:`governance` |
  :ref:`change-proposal-process` |
  :doc:`dev/style/index`

* **Building and Running**:
  :doc:`dev/setup` |
  :doc:`dev/build` |
  :doc:`dev/run` |
  :doc:`dev/dependencies` |
  :doc:`dev/testing/index`

* :doc:`dev/design/index`
