# SCMP

Example usage of scmp tool for echo (a.k.a. ping):

```bash
make
./bin/scmp echo -remote 2-ff00:0:222,[127.0.0.228]
```

You can run scmp tool in Interactive mode with -i flag to be able to choose
one of the available paths.

For information of other flags run:

```bash
./bin/scmp -h
```
