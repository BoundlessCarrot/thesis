const std = @import("std");
const testing = @import("testing");
const Rabbit = @import("rabbit.zig");

pub fn clear(dest: []u8, dataSize: usize) void {
    for (dest) |elem, i| {
        if (i == dataSize) break;
        elem.* = 0;
    }
}

pub fn testIfEqual(src1: []const u8, src2: []const u8, dataSize: usize) bool {
    for (src1) |elem1, i| {
        if (i == dataSize) break;
        if (elem1 != src2[i]) return false;
    }
    return true;
}

test "Rabbit Cipher Test" {
    var key1: [16]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var iv1: [8]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var out1: [16]u8 = .{ 0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7, 0xC6 };

    var rMasterInst: Rabbit.rabbit_instance = undefined;
    var rInst: Rabbit.rabbit_instance = undefined;
    var buffer: [16]u8 = undefined;

    try Rabbit.rabbit_key_setup(&rMasterInst, &key1);
    try Rabbit.rabbit_iv_setup(&rMasterInst, &rInst, &iv1);
    try Rabbit.rabbit_cipher(&rInst, &rInst, &buffer, 8);

    std.testing.expect(testIfEqual(&buffer, &out1, 16));
}

// pub fn main() !void {
//     const allocator = std.mem.Allocator;
//     var runner = std.testing.createRunner(allocator);

//     const group = &std.testing.createGroup(runner, "Rabbit Tests");

//     std.testing.groupAddTest(group, "Rabbit Cipher Test");

//     var result = std.testing.run(runner, allocator);
//     std.debug.assert(result.passed);
// }
