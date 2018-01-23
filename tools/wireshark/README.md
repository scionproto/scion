Wireshark plug-in
====
This wireshark dissector adds support for SCION packets.
Currently it supports SCION packets using the UDP/IP overlay, with
source/destination ports of 30000-32000 (intra-AS traffic) and 50000-50050
(inter-AS traffic).

Install
-----------
This extension requires a wireshark with Lua support enabled, and can be used
by making it accessible in the [wireshark plugin
directory](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)
* On ubuntu 16.04, this is `~/.wireshark/plugins/`

This has been tested with Wireshark 2.2.6 on ubuntu 16.04, and Wireshark 2.4.2 on Windows 7.
