# SCION Chrome Proxy Visualization Extensions

To install in Chrome (one time):

1. Open the Chrome browser.
1. Go to [chrome://extensions](chrome://extensions).
1. **Developer mode** should be checked.
1. Click **Load unpacked extension...**.
1. Select the local directory of the SCION Link Feeder Test extension: `chrome/ext`
1. Click **Load unpacked extension...** again.
1. Select the local directory of the SCION Visualization app: `chrome/app`
1. Configure proxy settings as needed by clicking on the SCION Link Feeder Test extension button to the right of the address window.
1. Select **Configure your proxy settings manually**, **HTTPHost**: 127.0.0.1, **Port**: 8080, and check **Use the same proxy server for all protocols**, click **Save proxy settings**.

To launch the proxy and knowledge-base (each run):

1. If running SCION, stop it: `./scion.sh stop`
1. Be sure the socket library is built: `./scion.sh sock_bld`
1. Run SCION: `./scion.sh run`
1. Start 4 processes in separate terminals:
1. `./scion.sh sock_ser`
1. `./scion.sh sock_cli`
1. `endhost/scion_proxy.py -f -s -k`
1. `endhost/scion_proxy.py -p 9090 -s -k`
1. Launch the SCION Visualization app by opening a new tab and clicking on the Apps button in the top left of the window. This can also be done by going to [chrome://apps](chrome://apps).
1. Click on any URL in the SCION Visualization app window to view SCION statistics.
