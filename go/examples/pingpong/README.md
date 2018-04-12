To run the ping-pong application on the default topology from AS1-ff00:0:133 to AS2-ff00:0:222,
first make sure the infrastructure is running.

Then, start the server using:
```
pingpong -mode server -local 2-ff00:0:222,[127.0.0.1]:40002
```

Finally, start the client using:
```
pingpong -mode client -remote 2-ff00:0:222,[127.0.0.1]:40002 -local 1-ff00:0:133,[127.0.0.1]:0 -count 10
```

When running the client in interactive mode, the user would be able to choose
the path used. A side effect is that the application will not adapt to path
updates, whereas snet will manage path updates when running in non-interactive
mode.
