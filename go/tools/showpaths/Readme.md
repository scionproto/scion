To show the SCION paths between two ISD-ASs, first make sure the infrastructure is running.

Then, run:
```
make
./bin/showpaths -dstIA 2-4_295_002_022 -srcIA 1-4_295_001_033
```

Alternatively, you can also run the application using:
```
go run paths.go -dstIA 2-4_295_002_022 -srcIA 1-4_295_001_033
```
In the examples above, the application will display the paths between 1-4_295_001_033 and 
2-4_295_002_022.

For complete options:
```
go run paths.go -h
```
