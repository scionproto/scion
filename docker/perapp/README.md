# Per-application Docker images for SCION

Per-application Docker images for SCION

## Images

- Build base images {app_builder, app_base, python, debug}: `make base`
- Build app images: `make apps`
- Build debug images: `make debug`

Build all images: `make all`. Build bazel images: `make bazel`.

### Base Images

- app_base: Contains `libc`, `libcap2` and `su-exec`
- app_builder: Contains compiled app binaries
- debug: `strace` and toybox
- python: base image plus python and pip packages and python code

### App Images

Following the list of images built by Bazel:

- border: Runs `/app/border`
- beacon_srv: Runs `/app/beacon_srv`
- cert_srv: Runs `/app/cert_srv`
- dispatcher_go: Runs `/app/godispatcher`
- path_srv: Runs `/app/path_srv`
- sciond: Runs `/app/sciond`
- sig: Runs `/app/sig`

## Debug images

One image for each of the base and app images, combined with the debug image.
