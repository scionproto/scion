*********
Wireshark
*********

To inspect SCION packets that are sent over the wire it can be helpful to use
Wireshark.
For this, we have a Wireshark SCION packet dissector plugin, :download:`scion.lua </../tools/wireshark/scion.lua>`.

Install Wireshark
^^^^^^^^^^^^^^^^^

Wireshark is available from the standard package repositories in most OS distributions (:command:`apt`, :command:`yum`, :command:`pacman`, etc).
More details, and installers for Windows and MacOS, can be found on the
`Wireshark download page <https://www.wireshark.org/download.html>`_.


.. Note::

   The scion.lua plugin requires version 3.x of Wireshark, which is not shipped
   by default on older versions of Ubuntu, like 18.04. Use ``ppa:wireshark-dev/stable``
   to install a more recent version:

   .. code-block:: bash

      sudo add-apt-repository ppa:wireshark-dev/stable
      sudo apt-get update
      sudo apt-get install wireshark


Install the SCION packet dissector plugin
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Store the :download:`scion.lua </../tools/wireshark/scion.lua>` plugin file to
the `Wireshark plugin folder <https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html>`_.
This folder needs to be created if it doesn't exist.

- ``$HOME/.config/wireshark/plugins`` for most Linux distributions
- Windows:  ``%APPDATA%\Wireshark\plugins``
- MacOS:    ``/Applications/Wireshark.app/Contents/PlugIns/wireshark``


In the Wireshark GUI, the dialog :guilabel:`Analyze`:menuselection:`-->`:guilabel:`Enabled Protocols`
should now list multiple protocols related to SCION.

After that you can test it by running a topology and using a SCION filter, for
example::

    scion.dst_as == "ff00:0:110"

.. Note::

   The :command:`tshark` command-line frontend for Wireshark lists the installed plugins with::

      tshark -G plugins

Work remotely with Wireshark
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Sometimes it can be handy to use the remote feature of wireshark to tap into an
interface on a different machine.


#. Install wireshark on your local OS and install the dissector plugin (see above)

#. Prepare the remote machine

   Install tcpdump::

      sudo apt-get install tcpdump

   The user used to SSH into the remote machine needs to have full access to tcpdump.
   Hence create a new group and add this user to the group. SSH into the remote machine
   and execute::

      sudo groupadd pcap
      sudo usermod -a -G pcap $USER

   set this group as the owner of tcpdump::

      sudo chgrp pcap /usr/sbin/tcpdump
      sudo chmod 750 /usr/sbin/tcpdump

   give tcpdump the necessary permissions::

      sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

   .. note::
      This will allow every user part of the pcap group to use the full
      capabilities of tcpdump!

#. Figure out the network interface on the remote host you want to tap into:
   Get an IP address used by the SCION topology that's probably running with docker.
   Search for the network-interface that's with the corresponding subnet.

#. Start wireshark and click on the gear next to the interface named
   "SSH remote capture: sshdump".
   Fill in the IP address and Port of the remote host, as well as your preferred
   authentication method in the Authentication tab.
   At the Capture tab write the name of the interface you found in the previous
   step. Find the a screenshot of an example below:

   .. image:: wireshark.png

#. Now you are ready to click start and investigate some SCION traffic
