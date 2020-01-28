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

### Debug images

One image for each of the base and app images, combined with the debug image.

## Running environment (and su-exec)

There are several constraints in how the images work:

1. Containers shouldn't run as root, or have suid binaries in them.
1. File-based access is needed when running to connect to the dispatcher, read config
   files, write logs, etc. This means the container needs to run as a specific user in
   order to have the correct permissions.
1. The dispatcher socket needs to be available to processes running directly on the
   host (e.g. `scmp`, `showpaths -p`). This means we can't run everything in a
   docker volume independant of the host environment.
1. The user (i.e. uid+gid(s)) that the container process will run as is not known at
   build time, because it depends on the host environment it is deployed on top of.

The simple approach would be to do something like this:

```bash
docker run -v /etc/passwd:/etc/passwd -v /etc/group:/etc/group -u $LOGNAME <image>
```

Unfortunately the `-u` flag takes effect before the volumes get mounted, causing
the user change to fail.

This is solved by using [su-exec](https://github.com/anapaya/su-exec) as the entrypoint.
`su-exec` runs as `root`, after docker has finished creating the container. This means
the volumes are already mounted. `su-exec` reads from the `SU_EXEC_USERSPEC` environment
variable (in the form `user[:group]`), changes to the specified user/group, and then
exec's its cmdline arguments (in this case the image's service binary).

```bash
docker run -v /etc/passwd:/etc/passwd -v /etc/group:/etc/group -e SU_EXEC_USERSPEC=$LOGNAME <image>
```
