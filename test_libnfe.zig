const std = @import("std");

const AppError = error{
    LoadLibraryFailed,
    GetProcAddressFailed,
    StatusServicoFailed,
};

// Function signature for the DLL export
const StatusServicoFunc = fn () callconv(.C) ?[*:0]const u8;

pub fn main() !void {
    // Load the DLL
    var lib = try std.DynLib.open("libnfe.dll");
    defer lib.close();

    // Get function pointer
    const status_servico = lib.lookup(*const StatusServicoFunc, "status_servico") orelse {
        std.debug.print("Failed to get status_servico\n", .{});
        return AppError.GetProcAddressFailed;
    };

    // Call the status_servico function
    const response = status_servico() orelse {
        std.debug.print("status_servico returned null\n", .{});
        return AppError.StatusServicoFailed;
    };

    // Convert C string to Zig string and print
    const response_str = std.mem.span(response);
    try std.io.getStdOut().writer().print("Response:\n{s}\n", .{response_str});
}
