The raw packets were created as follows:
```
./tools/pktcap 127.2.2.222 go/border/rpkt/testdata/udp-scion.bin &
# Wait for it to say Capturing on 'Loopback'
./tools/pktgen.py 1-ff00:0:133 127.1.1.111 2-ff00:0:222 127.2.2.222
```

You can view the contents of them using pktprint.py:
```
./tools/pktprint.py $(xxd -p  go/border/hpkt/testdata/udp-scion.bin)
```
