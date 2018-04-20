Example usage of scmp tool for echo (a.k.a. ping):
```
make
./bin/scmp -local 1-ff00:0:133,[127.0.0.75] -remote 2-ff00:0:222,[127.0.0.228]
```

You can run scmp tool in Interactive mode with -i flag to be able to choose
one of the available paths.

For information of other flags run:
```
./bin/scmp -h
```
