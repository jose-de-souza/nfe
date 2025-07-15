const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "libnfe",
        .root_source_file = b.path("libnfe.zig"),
        .target = target,
        .optimize = optimize,
    });

    // OpenSSL paths using cwd_relative, ensuring correct path
    const openssl_include = "C:/Program Files/OpenSSL-Win64/include";
    const openssl_lib = "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD";
    lib.addIncludePath(.{ .cwd_relative = openssl_include });
    lib.addLibraryPath(.{ .cwd_relative = openssl_lib });
    lib.linkSystemLibrary("libcrypto");
    lib.linkSystemLibrary("libssl");
    lib.linkLibC();

    b.installArtifact(lib);
}
