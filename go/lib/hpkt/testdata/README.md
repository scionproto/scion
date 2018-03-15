The raw packets were created as follows:
```
./tools/pktcap 127.2.2.222 go/lib/hpkt/testdata/udp-scion.bin &
# Wait for it to say Capturing on 'Loopback'
./tools/pktgen.py 1-10 127.1.1.111 2-25 127.2.2.222
./tools/pktcap 127.1.1.111 go/lib/hpkt/testdata/scmp-rev.bin &
# Wait for it to say Capturing on 'Loopback'
./supervisor/supervisor.sh mstop '*:br2-25-*'; sleep 5; ./tools/pktgen.py 1-10 127.1.1.111 2-25 127.2.2.222; ./supervisor/supervisor.sh mstart '*:br2-25-*'
```

You can view the contents of them using pktprint.py:
```
./tools/pktprint.py $(xxd -p  go/lib/hpkt/testdata/udp-scion.bin)
```
