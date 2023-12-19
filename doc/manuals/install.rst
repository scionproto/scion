************
Installation
************

Debian packages
===============

Installation packages for Debian and derivatives are available for x86-64, arm64, x86-32 and arm.

These packages can be found in the `latest release <https://github.com/scionproto/scion/releases/latest>`_.
Packages for in-development versions can be found from the `latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest>`_.

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


Prebuilt Binaries
=================

"Naked" pre-built binaries are available for Linux x86-64 and
can be downloaded from the `latest release <https://github.com/scionproto/scion/releases/latest>`_,
or from the `latest nightly build <https://buildkite.com/scionproto/scion-nightly/builds/latest>`_.

These binaries are statically linked and can run with little requirements on the operating system.


.. seealso::

   :doc:`/dev/build`
      Instructions for :doc:`building from source </dev/build>`.
