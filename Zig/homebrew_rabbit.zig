const std = @import("std");
const bytesToValue = std.mem.bytesToValue;
const asBytes = std.mem.asBytes;
const WORDSIZE = 0x100000000;

pub const RabbitInstance = struct {
    b: u8,
    c: [8]u32,
    g: [8]u32,
    k: [8][16]u32,
    s: [16]u8,
    x: [8]u32,

    const Self = @This();

    pub fn init(key: [128]u32) RabbitInstance {
        return RabbitInstance{
            .b = 0,
            .c = undefined,
            .g = undefined,
            .k = [8][16]u32{ key[0..16], key[16..32], key[32..48], key[48..64], key[64..80], key[80..96], key[96..112], key[112..128] },
            .s = undefined,
            .x = undefined,
        };
    }

    fn arrToInt(comptime T: type, slice: []u8) T {
        var result: T = 0;

        for (slice) |bit| {
            // Shift the result left or add the current bit
            result = (result << 1) | bit;
        }

        return result;
    }

    pub fn key_setup(self: Self) void {
        var idx: u8 = 0;
        while (idx != 8) : (idx += 1) {
            if (idx % 2 == 0) {
                self.x[idx] = bytesToValue(u32, asBytes(&self.k[(idx + 1 % 8)]) ++ asBytes(&self.k[idx]));
                self.c[idx] = bytesToValue(u32, asBytes(&self.k[(idx + 4 % 8)]) ++ asBytes(&self.k[idx]));
            } else {
                self.x[idx] = bytesToValue(u32, asBytes(&self.k[(idx + 5 % 8)]) ++ asBytes(&self.k[(idx + 4 % 8)]));
                self.c[idx] = bytesToValue(u32, asBytes(&self.k[idx]) ++ asBytes(&self.k[(idx + 1 % 8)]));
            }
        }

        var idx2: u8 = 0;
        while (idx2 < 4) : (idx2 += 1) {
            counter_update(self);
            next_state(self);
        }

        for (self.c) |*c, i| {
            c.* ^= self.x[(i + 4 % 8)];
        }
    }

    pub fn next_state(self: Self) void {
        var idx: u8 = 0;
        var g: [8]u32 = undefined;
        while (idx != 8) : (idx += 1) {
            g[idx] = g_func(bytesToValue(u32, self.x[idx] ++ self.c[idx]));
        }

        self.x[0] = g[0] + (g[7] << 16) + (g[6] << 16) % WORDSIZE;
        self.x[1] = g[1] + (g[0] << 8) + g[7] % WORDSIZE;
        self.x[2] = g[2] + (g[1] << 16) + (g[0] << 16) % WORDSIZE;
        self.x[3] = g[3] + (g[2] << 8) + g[1] % WORDSIZE;
        self.x[4] = g[4] + (g[3] << 16) + (g[2] << 16) % WORDSIZE;
        self.x[5] = g[5] + (g[4] << 8) + g[3] % WORDSIZE;
        self.x[6] = g[6] + (g[5] << 16) + (g[4] << 16) % WORDSIZE;
        self.x[7] = g[7] + (g[6] << 8) + g[5] % WORDSIZE;
    }

    fn g_func(x: u32) u32 {
        // Temporary variables
        // Construct high and low argument for squaring
        var high: u32 = x & 0xFFFF;
        var low: u32 = x >> 16;

        // Calculate high and low result of squaring
        var h: u32 = ((((high * high) >> 17) + (high * low)) >> 15) + (low * low);
        var l: u32 = x * x;

        // Return high XOR low
        return h ^ l;
    }

    fn extraction(self: Self) void {
        self.s[0..2] = asBytes(bytesToValue(u16, asBytes(&self.x[0])[0..2]) ^ bytesToValue(u16, asBytes(&self.x[5])[2..4]));
        self.s[2..4] = asBytes(bytesToValue(u16, asBytes(&self.x[0])[2..4]) ^ bytesToValue(u16, asBytes(&self.x[3])[0..2]));
        self.s[4..6] = asBytes(bytesToValue(u16, asBytes(&self.x[2])[0..2]) ^ bytesToValue(u16, asBytes(&self.x[7])[2..4]));
        self.s[6..8] = asBytes(bytesToValue(u16, asBytes(&self.x[2])[2..4]) ^ bytesToValue(u16, asBytes(&self.x[5])[0..2]));
        self.s[8..10] = asBytes(bytesToValue(u16, asBytes(&self.x[4])[0..2]) ^ bytesToValue(u16, asBytes(&self.x[1])[2..4]));
        self.s[10..12] = asBytes(bytesToValue(u16, asBytes(&self.x[4])[2..4]) ^ bytesToValue(u16, asBytes(&self.x[7])[0..2]));
        self.s[12..14] = asBytes(bytesToValue(u16, asBytes(&self.x[6])[0..2]) ^ bytesToValue(u16, asBytes(&self.x[3])[2..4]));
        self.s[14..16] = asBytes(bytesToValue(u16, asBytes(&self.x[6])[2..4]) ^ bytesToValue(u16, asBytes(&self.x[1])[0..2]));
    }

    pub fn crypt(self: Self, data: [16]u8, output_buf: [16]u8) [16]u8 {
        var idx: u8 = 0;
        while (idx != 16) : (idx += 1) {
            output_buf[idx] = data[idx] ^ self.s[idx];
        }

        counter_update(self);
        next_state(self);
        extraction(self);
        return output_buf;
    }

    pub fn counter_update(self: Self) void {
        const a: [8]u32 = .{ 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3 };
        var idx: u8 = 0;
        while (idx != 8) : (idx += 1) {
            var temp = self.c[idx] + a[idx] + self.b;
            self.b = temp / WORDSIZE;
            self.c[idx] = temp % WORDSIZE;
        }
    }

    pub fn iv_setup(self: Self, iv: [64]u8) void {
        self.c[0] ^= arrToInt(u32, iv[0..32]);
        self.c[2] ^= arrToInt(u32, iv[32..64]);
        self.c[4] ^= arrToInt(u32, iv[0..32]);
        self.c[6] ^= arrToInt(u32, iv[32..64]);

        self.c[1] ^= arrToInt(u32, iv[48..64] ++ iv[16..32]);
        self.c[3] ^= arrToInt(u32, iv[32..48] ++ iv[0..16]);
        self.c[5] ^= arrToInt(u32, iv[16..32] ++ iv[48..64]);
        self.c[7] ^= arrToInt(u32, iv[0..16] ++ iv[32..48]);

        var idx: u8 = 0;
        while (idx < 4) : (idx += 1) {
            counter_update(self);
            next_state(self);
        }
    }
};

