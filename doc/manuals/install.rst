************
Installation
************

.. _install-debian-packages:

Debian packages
===============

Installation packages for Debian and derivatives are available for x86-64, arm64, x86-32 and arm.

These packages can be found in the `latest release <https://github.com/scionproto/scion/releases/latest>`_.
Packages for in-development versions can be found from the `latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest>`_.

Download and unpack the tar.gz file containing the appropriate .deb packages.
Install all packages with ``apt install ./scion-*.deb``, or install packages for components
selectively, e.g. ``apt install ./scion-router_<version>_<arch>.deb``.

.. warning::

   Tests are run only for x86-64. For the other platforms, we cross-compile and don't operate a
   corresponding test infrastructure. We plan to add test infrastructure also for arm64, but not for
   the 32 bit platforms.

.. note::

   There is currently no apt repository from which the packages can be installed directly.

.. hint::

   **Systemd**

   The packages include systemd units which can be used to run the SCION components.
   There are various introduction documents on how to interact with systemd, for example
   https://wiki.archlinux.org/title/Systemd#Using_units, or https://linuxhandbook.com/systemctl-commands/.

   Very briefly:

   * ``systemctl start <unit>`` / ``systemctl stop <unit>``: start/stop a unit immediately
   * ``systemctl enable <unit>`` / ``systemctl disable <unit>``: enable/disable a unit to start automatically at boot
   * ``systemctl status <unit>``: display the status of a unit
   * ``journalct -u <unit>``: show log of unit


Packages
--------

:doc:`scion-control <control>`
   :Executable: ``/usr/bin/scion-control``
   :Systemd Unit:
      The ``scion-control@.service`` systemd unit template file allows running multiple program
      instances per host.
      Create one :ref:`control-conf-toml` file per program instance in ``/etc/scion``.
      The basename of the configuration file is the instance parameter (the part after the ``@``) for
      the corresponding systemd template unit instance.

      Example: create configuration ``/etc/scion/cs-1.toml`` and start
      ``systemctl start scion-control@cs-1.service``.

:doc:`scion-router <router>`
   :Executable: ``/usr/bin/scion-router``
   :Systemd Unit:
      The ``scion-router@.service`` systemd unit template file allows running multiple program
      instances per host.
      Create one :ref:`router-conf-toml` file per router instance in ``/etc/scion``.
      The basename of the configuration file is the instance parameter (the part after the ``@``) for
      the corresponding systemd template unit instance.

      Example: create configuration ``/etc/scion/br-1.toml`` and start
      ``systemctl start scion-router@br-1.service``.

:doc:`scion-ip-gateway <gateway>`
   :Executable: ``/usr/bin/scion-ip-gateway``
   :Systemd Unit:
      The ``scion-ip-gateway.service`` systemd unit refers to the default ``/etc/scion/sig.toml``
      configuration and the traffic policy file ``/etc/scion/sig.json``.
      The default traffic policy file is incomplete and must be edited before starting the service.

:doc:`scion-daemon <daemon>`
   The scion-daemon and the scion-dispatcher together form the end host SCION stack.

   :Executable: ``/usr/bin/scion-daemon``
   :Systemd Unit:
      The ``scion-daemon.service`` systemd unit refers to the default
      ``/etc/scion/sciond.toml`` configuration file.

:doc:`scion-dispatcher <dispatcher>`
   :Executable: ``/usr/bin/scion-dispatcher``
   :Systemd Unit:
      The ``scion-dispatcher.service`` systemd unit refers to the default
      ``/etc/scion/dispatcher.toml`` configuration file.

scion-tools
   The :doc:`scion </command/scion/scion>` and :doc:`scion-pki</command/scion-pki/scion-pki>`
   command line tools.

   :Executables: ``/usr/bin/scion``, ``/usr/bin/scion-pki``

.. admonition:: Note

   The configuration manuals for gateway, daemon and dispatcher are currently incomplete.

   In the meantime, the ``sample config`` subcommand (e.g. ``scion-daemon sample config``)
   describes the available configuration options.



OpenWRT packages
================

Installation packages for OpenWRT are available for x86-64 (cross-building for other architectures
should be feasible but has not yet been implemented).

These packages can be found in the `latest release <https://github.com/scionproto/scion/releases/latest>`_.
Packages for in-development versions can be found from the `latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest>`_.

Download and unpack the tar.gz file containing the appropriate .ipk packages.
Install all packages with ``opgk install ./scion-*.ipk``, or install packages for components
selectively, e.g. ``opgk install ./scion-router_<version>_<arch>.ipk``.

The packages include init scripts which start the SCION components as part of the OpenWRT boot process.
See the `OpenWRT manual on managing services <https://openwrt.org/docs/guide-user/base-system/managing_services>`_.

.. admonition:: Note

   To save space on often storage constrained OpenWRT devices, the relatively large golang
   binaries are installed as self-uncompressing, gzipped executables.

Packages
--------

:doc:`scion-control <control>`
   :Executable: ``/usr/bin/scion-control``
   :Service: ``scion-control``
   :Service Configuration File: ``/etc/scion/control.toml``

:doc:`scion-router <router>`
   :Executable: ``/usr/bin/scion-router``
   :Service: ``scion-router``
   :Service Configuration File: ``/etc/scion/router.toml``

:doc:`scion-ip-gateway <gateway>`
   :Executable: ``/usr/bin/scion-gateway``
   :Service: ``scion-gateway``
   :Service Configuration File: ``/etc/scion/gateway.toml``

:doc:`scion-daemon <daemon>`
   The scion-daemon and the scion-dispatcher together form the end host SCION stack.

   :Executable: ``/usr/bin/scion-daemon``
   :Service: ``scion-daemon``
   :Service Configuration File: ``/etc/scion/daemon.toml``

:doc:`scion-dispatcher <dispatcher>`
   :Executable: ``/usr/bin/scion-dispatcher``
   :Service: ``scion-dispatcher``
   :Service Configuration File: ``/etc/scion/dispatcher.toml``

scion-tools
   The :doc:`scion </command/scion/scion>` and :doc:`scion-pki</command/scion-pki/scion-pki>`
   command line tools.

   :Executables: ``/usr/bin/scion``, ``/usr/bin/scion-pki``

scion-persistdbs
   Helper service to persist databases of ``scion-control`` and ``scion-daemon`` services from volatile storage before shutdown.
   At runtime, databases are in volatile storage ``/var/lib/scion``.
   For persistence, the files are moved to ``/usr/lib/scion``.


Prebuilt Binaries
=================

"Naked" pre-built binaries are available for Linux x86-64 and
can be downloaded from the `latest release <https://github.com/scionproto/scion/releases/latest>`_,
or from the `latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest>`_.

These binaries are statically linked and can run with little requirements on the operating system.


.. seealso::

   :doc:`/dev/build`
      Instructions for :doc:`building from source </dev/build>`.
