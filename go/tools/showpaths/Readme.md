# Showpaths

To show the SCION paths between two ISD-ASs, first make sure the infrastructure is running.

Then, run:

```bash
make
./bin/showpaths -dstIA 2-ff00:0:222 -srcIA 1-ff00:0:133
```

Alternatively, you can also run the application using:

```bash
go run paths.go -dstIA 2-ff00:0:222 -srcIA 1-ff00:0:133
```

In the examples above, the application will display the paths between 1-ff00:0:133 and
2-ff00:0:222.

For complete options:

```bash
go run paths.go -h
```
