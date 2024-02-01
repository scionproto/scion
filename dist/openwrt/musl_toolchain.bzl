# Verbatim from illicitonion's unreleased work:
# https://github.com/bazel-contrib/musl-toolchain

load(
    "@bazel_tools//tools/build_defs/cc:action_names.bzl",
    _ASSEMBLE_ACTION_NAME = "ASSEMBLE_ACTION_NAME",
    _CLIF_MATCH_ACTION_NAME = "CLIF_MATCH_ACTION_NAME",
    _CPP_COMPILE_ACTION_NAME = "CPP_COMPILE_ACTION_NAME",
    _CPP_HEADER_PARSING_ACTION_NAME = "CPP_HEADER_PARSING_ACTION_NAME",
    _CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME = "CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME",
    _CPP_LINK_EXECUTABLE_ACTION_NAME = "CPP_LINK_EXECUTABLE_ACTION_NAME",
    _CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME = "CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME",
    _CPP_LINK_STATIC_LIBRARY_ACTION_NAME = "CPP_LINK_STATIC_LIBRARY_ACTION_NAME",
    _CPP_MODULE_CODEGEN_ACTION_NAME = "CPP_MODULE_CODEGEN_ACTION_NAME",
    _CPP_MODULE_COMPILE_ACTION_NAME = "CPP_MODULE_COMPILE_ACTION_NAME",
    _C_COMPILE_ACTION_NAME = "C_COMPILE_ACTION_NAME",
    _LINKSTAMP_COMPILE_ACTION_NAME = "LINKSTAMP_COMPILE_ACTION_NAME",
    _LTO_BACKEND_ACTION_NAME = "LTO_BACKEND_ACTION_NAME",
    _PREPROCESS_ASSEMBLE_ACTION_NAME = "PREPROCESS_ASSEMBLE_ACTION_NAME",
)
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "action_config",
    "feature",
    "flag_group",
    "flag_set",
    "tool",
    "tool_path",
    "with_feature_set",
    "env_set",
    "env_entry",
)

all_link_actions = [
    _CPP_LINK_EXECUTABLE_ACTION_NAME,
    _CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME,
    _CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME,
]

def _impl(ctx):
    target_arch = ctx.attr.target_arch
    target_cpu = "k8" if ctx.attr.target_arch == "x86_64" else "arm64"

    objcopy_embed_data_action = action_config(
        action_name = "objcopy_embed_data",
        enabled = True,
        tools = [tool(path = "bin/" + target_arch + "-openwrt-linux-musl-objcopy")],
    )
    path_prefix = "staging_dir/toolchain-" + target_arch + "_gcc-12.3.0_musl/bin/" + target_arch
    tool_paths = [
        tool_path(name = "gcc", path = path_prefix + "-openwrt-linux-musl-gcc"),
        tool_path(name = "ld", path = path_prefix + "-openwrt-linux-musl-ld"),
        tool_path(name = "compat-ld", path = path_prefix + "-openwrt-linux-musl-ld"),
        tool_path(name = "ar", path = path_prefix + "-openwrt-linux-musl-ar"),
        tool_path(name = "cpp", path = path_prefix + "-openwrt-linux-musl-cpp"),
        tool_path(name = "gcov", path = path_prefix + "-openwrt-linux-musl-gcov"),
        tool_path(name = "nm", path = path_prefix + "-openwrt-linux-musl-nm"),
        tool_path(name = "objcopy", path = path_prefix + "-openwrt-linux-musl-objcopy"),
        tool_path(name = "objdump", path = path_prefix + "-openwrt-linux-musl-objdump"),
        tool_path(name = "strip", path = path_prefix + "-openwrt-linux-musl-strip"),
        tool_path(name = "dwp", path = "/usr/bin/false"),
    ]

    default_link_flags_feature = feature(
        name = "default_link_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = [
                            "-lstdc++",
                            "-Wl,-z,relro,-z,now",
                            "-no-canonical-prefixes",
                            "-pass-exit-codes",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = all_link_actions,
                flag_groups = [flag_group(flags = ["-Wl,--gc-sections"])],
                with_features = [with_feature_set(features = ["opt"])],
            ),
        ],
    )

    unfiltered_compile_flags_feature = feature(
        name = "unfiltered_compile_flags",
        enabled = True,
        env_sets = [
            env_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                env_entries = [
                    env_entry("STAGING_DIR", "external/openwrt_SDK/staging_dir"),
                ],
            ),
        ],
        flag_sets = [
            flag_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-Iexternal/openwrt_SDK/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/x86_64-openwrt-linux-musl/sys-include",
                            "-Iexternal/openwrt_SDK/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/include",
                            "-Iexternal/openwrt_SDK/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/x86_64-openwrt-linux-musl/include",
                            "-Iexternal/openwrt_SDK/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/lib/gcc/x86_64-openwrt-linux-musl/12.3.0/include",
                            "-nostdinc",
                            # "-no-canonical-prefixes",
                            # "-fno-canonical-system-headers",
                            "-Wno-builtin-macro-redefined",
                            "-D_LARGEFILE64_SOURCE", # BW compat
                            # "-D__DATE__=\"redacted\"",
                            # "-D__TIMESTAMP__=\"redacted\"",
                            # "-D__TIME__=\"redacted\"",
                        ],
                    ),
                ],
            ),
        ],
    )

    supports_pic_feature = feature(name = "supports_pic", enabled = True)

    default_compile_flags_feature = feature(
        name = "default_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            # "-U_FORTIFY_SOURCE",
                            # "-D_FORTIFY_SOURCE=1",
                            # "-fstack-protector",
                            # "-Wall",
                            # "-Wunused-but-set-parameter",
                            "-Wno-free-nonheap-object",
                            # "-fno-omit-frame-pointer",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [flag_group(flags = ["-g"])],
                with_features = [with_feature_set(features = ["dbg"])],
            ),
            flag_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-g0",
                            "-O2",
                            "-DNDEBUG",
                            "-ffunction-sections",
                            "-fdata-sections",
                        ],
                    ),
                ],
                with_features = [with_feature_set(features = ["opt"])],
            ),
            flag_set(
                actions = [
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [flag_group(flags = ["-std=c++14"])],
            ),
        ],
    )

    opt_feature = feature(name = "opt")

    supports_dynamic_linker_feature = feature(name = "supports_dynamic_linker", enabled = True)

    objcopy_embed_flags_feature = feature(
        name = "objcopy_embed_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = ["objcopy_embed_data"],
                flag_groups = [flag_group(flags = ["-I", "binary"])],
            ),
        ],
    )

    dbg_feature = feature(name = "dbg")

    user_compile_flags_feature = feature(
        name = "user_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    _ASSEMBLE_ACTION_NAME,
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["%{user_compile_flags}"],
                        iterate_over = "user_compile_flags",
                        expand_if_available = "user_compile_flags",
                    ),
                ],
            ),
        ],
    )

    sysroot_feature = feature(
        name = "sysroot",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    _PREPROCESS_ASSEMBLE_ACTION_NAME,
                    _LINKSTAMP_COMPILE_ACTION_NAME,
                    _C_COMPILE_ACTION_NAME,
                    _CPP_COMPILE_ACTION_NAME,
                    _CPP_HEADER_PARSING_ACTION_NAME,
                    _CPP_MODULE_COMPILE_ACTION_NAME,
                    _CPP_MODULE_CODEGEN_ACTION_NAME,
                    _LTO_BACKEND_ACTION_NAME,
                    _CLIF_MATCH_ACTION_NAME,
                    _CPP_LINK_EXECUTABLE_ACTION_NAME,
                    _CPP_LINK_DYNAMIC_LIBRARY_ACTION_NAME,
                    _CPP_LINK_STATIC_LIBRARY_ACTION_NAME,
                    _CPP_LINK_NODEPS_DYNAMIC_LIBRARY_ACTION_NAME,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["--sysroot=%{sysroot}"],
                        expand_if_available = "sysroot",
                    ),
                ],
            ),
        ],
    )

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        toolchain_identifier = target_cpu + "-musl-toolchain",
        host_system_name = "local",
        target_system_name = "local",
        target_cpu = target_cpu,
        target_libc = "musl",
        compiler = "gcc",
        abi_version = "local",
        abi_libc_version = "local",
        tool_paths = tool_paths,
        action_configs = [objcopy_embed_data_action],
        features = [
            default_compile_flags_feature,
            default_link_flags_feature,
            supports_dynamic_linker_feature,
            supports_pic_feature,
            objcopy_embed_flags_feature,
            opt_feature,
            dbg_feature,
            user_compile_flags_feature,
            sysroot_feature,
            unfiltered_compile_flags_feature,
        ],
    )

musl_cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {
        "target_arch": attr.string(mandatory = True, values = ["aarch64", "x86_64"]),
    },
    provides = [CcToolchainConfigInfo],
)
