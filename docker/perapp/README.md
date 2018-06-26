# Per-application Docker images for SCION

Per-application Docker images for SCION

## Images

-   Build base images {app, base, python, debug}: `make base`
-   Build app images: `make apps`
-   Build debug images: `make debug`

Build all images: `make all`, specific image: `make border` or specific debug image:
`make border_debug`

### Base Images

-   app: Contains compiled app binaries
-   base: Contains `libc`, `libcap2` and `su-exec`
-   debug: `strace` and toybox
-   python: base image plus python and pip packages and python code

### App Images

-   dispatcher: Runs `/app/dispatcher`
-   border: Runs `/app/border`
-   sig: Runs `/app/sig`
-   beacon: Runs `/app/bin/beacon_server`
-   path: Runs `/app/bin/path_server`
-   certificate: Runs `/app/bin/cert_server`
-   sciond: Runs `/app/bin/sciond`

Dispatcher, sig and border are based on `base`, the other images on `python`.

## Debug images

One image for each of the base and app images, combined with the debug image.
