To run the ping-pong application on the default topology from AS1-19 to AS2-25,
first make sure the infrastructure is running.

Then, start the server using:
```
go run pingpong.go -mode server -local 2-25,[127.0.0.1]:40002 -count 10
```

Finally, start the client using:
```
go run pingpong.go -mode client -remote 2-25,[127.0.0.1]:40002 -local 1-19,[127.0.0.1]:0 -count 10
```
