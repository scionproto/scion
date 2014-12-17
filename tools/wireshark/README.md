Wireshark plug-in
====
This wireshark plugin parses SCION packets and shows SCION parameters of the packets.
It supports, SCION packets on Ethernet frame and encapsulated SCION packet using IP and UDP.
Currently, it hooks ethertype=0x3333, IP.proto=40 and UDP destination ports from 33300 to 33399.

Install
-----------
Lua plugin is enabled in latest version wireshark,so put the plugin file (scion.lua) to wireshark plugin directory.
* For Linux: /usr/lib/x86_64-linux-gnu/wireshark/libwireshark3/plugins/
* For Windows :/ C:\Program Files\Wireshark\plugins\[version number]

Limitations
---------------------
Current version can parse data packet only.  
Wireshark version 1.10.6 on Linux and 1.12.1 on Windows have been tested.
