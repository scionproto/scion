# Per-application Docker images for SCION

Per-application Docker images for SCION

## Images

- Build base images {app_builder, debug}: `make base`
- Build app images: `make apps`
- Build debug images: `make debug`

Build all images: `make all`. Build bazel images: `make bazel`.

### Base Images

- app_builder: Contains compiled app binaries
- debug: `strace` and toybox

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
