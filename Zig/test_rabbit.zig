const std = @import("std");
const expect = std.testing.expect;
const rabbit = @import("homebrew_rabbit.zig");
const RabbitInstance = rabbit.RabbitInstance;
const key = .{ 0x91, 0x28, 0x13, 0x29, 0x2E, 0xED, 0x36, 0xFE, 0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC };

test "inner state post key expansion" {
    var r_inst = RabbitInstance.init(key);

    expect(r_inst.b == 0);
    expect(r_inst.x == .{ 0xDC51C3AC, 0x13292E3D, 0x3BFC62F1, 0xC3AC9128, 0x2E3D36FE, 0x62F1DC51, 0x91281329, 0x36FE3BFC });
    expect(r_inst.c == .{ 0x36FE2E3D, 0xDC5162F1, 0x13299128, 0x3BFC36FE, 0xC3ACDC51, 0x2E3D1329, 0x62F13BFC, 0x9128C3AC });
}

test "inner state after first key setup iteration" {
    var r_inst = RabbitInstance.init(key);

    r_inst.counter_update();
    r_inst.next_state();

    expect(r_inst.b == 1);
    expect(r_inst.x == .{ 0xF2E8C8B1, 0x38E06FA7, 0x9A0D72C0, 0xF21F5334, 0xCACDCCC3, 0x4B239CBE, 0x0565DCCC, 0xB1587C8D });
    expect(r_inst.c == .{ 0x8433018A, 0xAF9E97C4, 0x47FCDE5D, 0x89310A4B, 0x96FA1124, 0x6310605E, 0xB0260F49, 0x6475F87F });
}

// test "inner state after fourth key setup iteration" {}

// test "inner state after final key setup xor" {}

// test "inner state after generation of 48 bytes of output" {}
