To show the SCION paths between two ISD-ASs, first make sure the infrastructure is running.

Then, run the application using:
```
go run paths.go -dstIA 2-26 -srcIA 1-10
```
In the example above, the application will display the paths between 1-10 and 2-26.

For complete options:
```
go run paths.go -h
```

