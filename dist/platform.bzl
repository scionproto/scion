load("@aspect_bazel_lib//lib:transitions.bzl", "platform_transition_filegroup")

def multiplatform_filegroup(name, srcs, target_platforms, **kwargs):
    all_platforms = []
    for target_platform in target_platforms:
        platform_name = target_platform.split(":")[-1]
        platform_transition_filegroup(
            name = name + "_" + platform_name,
            srcs = srcs,
            target_platform = target_platform,
        )
        all_platforms.append(name + "_" + platform_name)

    native.filegroup(
        name = name + "_all",
        srcs = all_platforms,
        **kwargs
    )

    # also add the default filegroup, without platform transition, but
    # only build it when explicitly requested
    native.filegroup(
        name = name,
        srcs = srcs,
        tags = ["manual"],
        **kwargs
    )
