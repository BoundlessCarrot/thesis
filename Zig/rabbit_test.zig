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

test "Rabbit Key Setup and Cipher Test" {
    var key: [16]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var res: [48]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0xdb, 0x4c, 0x6f, 0x8a, 0x19, 0x34, 0x52, 0x7e, 0x20, 0x91, 0x67, 0x25, 0x58, 0x8b, 0x5e, 0x4b };

    std.testing.expect(testKeySetupAndCipher(&key, &res));
}

test "Rabbit Key Setup, IV Setup, and Cipher Test" {
    var key: [16]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var iv: [8]u8 = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var res: [48]u8 = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, 0xdb, 0x4c, 0x6f, 0x8a, 0x19, 0x34, 0x52, 0x7e, 0x20, 0x91, 0x67, 0x25, 0x58, 0x8b, 0x5e, 0x4b };

    std.testing.expect(testKeySetupIVSetupAndCipher(&key, &iv, &res));
}

pub fn testKeySetupAndCipher(key: []const u8, res: []const u8) bool {
    var rMasterInst: Rabbit.Instance = undefined;
    // var rInst: Rabbit.Instance = undefined;
    var buffer: [48]u8 = undefined;

    try Rabbit.keySetup(&rMasterInst, key);
    try Rabbit.cipher(&rMasterInst, &buffer, &buffer);

    return testIfEqual(&buffer, res, 48);
}

pub fn testKeySetupIVSetupAndCipher(key: []const u8, iv: []const u8, res: []const u8) bool {
    var rMasterInst: Rabbit.Instance = undefined;
    var rInst: Rabbit.Instance = undefined;
    var buffer: [48]u8 = undefined;

    try Rabbit.keySetup(&rMasterInst, key);
    try Rabbit.ivSetup(&rMasterInst, &rInst, iv);
    try Rabbit.cipher(&rInst, &buffer, &buffer);

    return testIfEqual(&buffer, res, 48);
}

pub fn main() !void {
    const allocator = std.testing.allocator;
    var runner = std.testing.createRunner(allocator);

    const group = &std.testing.createGroup(runner, "Rabbit Tests");

    std.testing.groupAddTest(group, "Rabbit Key Setup and Cipher Test");
    std.testing.groupAddTest(group, "Rabbit Key Setup, IV Setup, and Cipher Test");

    var result = std.testing.run(runner, allocator);
    std.debug.assert(result.passed);
}
