// rabbit.zig
// Rabbit Cipher

pub const rabbit_instance = struct {
    x: [8]u32,
    c: [8]u32,
    carry: u32,
    x0: [4]u8,
    x1: [4]u8,
    x2: [4]u8,
    x3: [4]u8,
    x4: [4]u8,
    x5: [4]u8,
    x6: [4]u8,
    x7: [4]u8,
};

// Left rotation of a 32-bit unsigned integer
fn rabbit_rotl(x: u32, rot: u32) u32 {
    return (x << rot) | (x >> (32 - rot));
}

// Square a 32-bit unsigned integer to obtain the 64-bit result and return
// the upper 32 bits XOR the lower 32 bits
fn rabbit_g_func(x: u32) u32 {
    // Temporary variables
    var a: u32 = undefined;
    var b: u32 = undefined;
    var h: u32 = undefined;
    var l: u32 = undefined;

    // Construct high and low argument for squaring
    a = x & 0xFFFF;
    b = x >> 16;

    // Calculate high and low result of squaring
    h = ((((a * a) >> 17) + (a * b)) >> 15) + (b * b);
    l = x * x;

    // Return high XOR low
    return h ^ l;
}

// Calculate the next internal state
fn rabbit_next_state(p_instance: *rabbit_instance) void {
    // Temporary variables
    var g: [8]u32 = undefined;
    var c_old: [8]u32 = undefined;
    var i: u8 = 0;

    // Save old counter values
    i = 0;
    while (i < 8) : (i += 1) {
        c_old[i] = p_instance.c[i];
    }

    // Calculate new counter values
    p_instance.c[0] += 0x4D34D34D + p_instance.carry;
    p_instance.c[1] += 0xD34D34D3 + (p_instance.c[0] < c_old[0]);
    p_instance.c[2] += 0x34D34D34 + (p_instance.c[1] < c_old[1]);
    p_instance.c[3] += 0x4D34D34D + (p_instance.c[2] < c_old[2]);
    p_instance.c[4] += 0xD34D34D3 + (p_instance.c[3] < c_old[3]);
    p_instance.c[5] += 0x34D34D34 + (p_instance.c[4] < c_old[4]);
    p_instance.c[6] += 0x4D34D34D + (p_instance.c[5] < c_old[5]);
    p_instance.c[7] += 0xD34D34D3 + (p_instance.c[6] < c_old[6]);
    p_instance.carry = (p_instance.c[7] < c_old[7]);

    // Calculate the g-functions
    i = 0;
    while (i < 8) : (i += 1) {
        g[i] = rabbit_g_func(p_instance.x[i] + p_instance.c[i]);
    }

    // Calculate new state values
    p_instance.x[0] = g[0] + rabbit_rotl(g[7], 16) + rabbit_rotl(g[6], 16);
    p_instance.x[1] = g[1] + rabbit_rotl(g[0], 8) + g[7];
    p_instance.x[2] = g[2] + rabbit_rotl(g[1], 16) + rabbit_rotl(g[0], 16);
    p_instance.x[3] = g[3] + rabbit_rotl(g[2], 8) + g[1];
    p_instance.x[4] = g[4] + rabbit_rotl(g[3], 16) + rabbit_rotl(g[2], 16);
    p_instance.x[5] = g[5] + rabbit_rotl(g[4], 8) + g[3];
    p_instance.x[6] = g[6] + rabbit_rotl(g[5], 16) + rabbit_rotl(g[4], 16);
    p_instance.x[7] = g[7] + rabbit_rotl(g[6], 8) + g[5];
}

// Initialize the cipher instance (*p_instance) as a function of the
// key (p_key)
pub fn rabbit_key_setup(p_instance: *rabbit_instance, p_key: []u8) !i32 {
    // Return error if the key size is not 16 bytes
    if (p_key.len != 16) {
        return -1;
    }

    // var k0_mask = ((1 << 5) - 1) << 0;
    // var k1_mask = ((1 << 5) - 1) << 4;
    // var k2_mask = ((1 << 5) - 1) << 8;
    // var k3_mask = ((1 << 5) - 1) << 12;

    // Temporary variables --> Generate four subkeys
    var k0: *[4]u8 = p_key[0..4];
    var k1: *[4]u8 = p_key[4..8];
    var k2: *[4]u8 = p_key[8..12];
    var k3: *[4]u8 = p_key[12..16];
    var i: u8 = 0;

    // Generate initial state variables
    p_instance.x0 = k0.*;
    p_instance.x2 = k1.*;
    p_instance.x4 = k2.*;
    p_instance.x6 = k3.*;
    p_instance.x1 = (k3.* << 16) | (k2.* >> 16);
    p_instance.x3 = (k0.* << 16) | (k3.* >> 16);
    p_instance.x5 = (k1.* << 16) | (k0.* >> 16);
    p_instance.x7 = (k2.* << 16) | (k1.* >> 16);

    // Generate initial counter values
    p_instance.c[0] = rabbit_rotl(k2, 16);
    p_instance.c[2] = rabbit_rotl(k3, 16);
    p_instance.c[4] = rabbit_rotl(k0, 16);
    p_instance.c[6] = rabbit_rotl(k1, 16);
    p_instance.c[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
    p_instance.c[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
    p_instance.c[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
    p_instance.c[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);

    // Clear carry bit
    p_instance.carry = 0;

    // Iterate the system four times
    i = 0;
    while (i < 4) : (i += 1) {
        rabbit_next_state(p_instance);
    }

    // Modify the counters
    i = 0;
    while (i < 8) : (i += 1) {
        p_instance.c[i] ^= p_instance.x[(i + 4) & 0x7];
    }

    // Return success
    return 0;
}

// Initialize the cipher instance (*p_instance) as a function of the
// IV (*p_iv) and the master instance (*p_master_instance)
pub fn rabbit_iv_setup(p_master_instance: *rabbit_instance, p_instance: *rabbit_instance, p_iv: [*]const u8, iv_size: usize) i32 {
    // Temporary variables
    var i_0: u32 = undefined;
    var i_1: u32 = undefined;
    var i_2: u32 = undefined;
    var i_3: u32 = undefined;
    var i: u8 = 0;

    // Return error if the IV size is not 8 bytes
    if (iv_size != 8) {
        return -1;
    }

    // Generate four subvectors
    i_0 = p_iv[0..4];
    i_2 = p_iv[4..8];
    i_1 = (i_0 >> 16) | (i_2 & 0xFFFF0000);
    i_3 = (i_2 << 16) | (i_0 & 0x0000FFFF);

    // Modify counter values
    p_instance.c[0] = p_master_instance.c[0] ^ i_0;
    p_instance.c[1] = p_master_instance.c[1] ^ i_1;
    p_instance.c[2] = p_master_instance.c[2] ^ i_2;
    p_instance.c[3] = p_master_instance.c[3] ^ i_3;
    p_instance.c[4] = p_master_instance.c[4] ^ i_0;
    p_instance.c[5] = p_master_instance.c[5] ^ i_1;
    p_instance.c[6] = p_master_instance.c[6] ^ i_2;
    p_instance.c[7] = p_master_instance.c[7] ^ i_3;

    // Copy internal state values
    i = 0;
    while (i < 8) : (i += 1) {
        p_instance.x[i] = p_master_instance.x[i];
    }
    p_instance.carry = p_master_instance.carry;

    // Iterate the system four times
    i = 0;
    while (i < 4) : (i += 1) {
        rabbit_next_state(p_instance);
    }

    // Return success
    return 0;
}

// Encrypt or decrypt data
pub fn rabbit_cipher(p_instance: *rabbit_instance, p_src: [*]const u8, p_dest: [*]u8, data_size: usize) i32 {
    // Temporary variables
    var i: usize = 0;

    // Return error if the size of the data to encrypt is
    // not a multiple of 16
    if (data_size % 16 != 0) {
        return -1;
    }

    i = 0;
    while (i < data_size) : (i += 16) {
        // Iterate the system
        rabbit_next_state(p_instance);

        // Encrypt 16 bytes of data
        p_dest[i] = p_src[i] ^ p_instance.x[0] ^
            (p_instance.x[5] >> 16) ^ (p_instance.x[3] << 16);
        p_dest[i + 1] = p_src[i + 1] ^ p_instance.x[2] ^
            (p_instance.x[7] >> 16) ^ (p_instance.x[5] << 16);
        p_dest[i + 2] = p_src[i + 2] ^ p_instance.x[4] ^
            (p_instance.x[1] >> 16) ^ (p_instance.x[7] << 16);
        p_dest[i + 3] = p_src[i + 3] ^ p_instance.x[6] ^
            (p_instance.x[3] >> 16) ^ (p_instance.x[1] << 16);
        p_dest[i + 4] = p_src[i + 4] ^ p_instance.x[0] ^
            (p_instance.x[5] >> 16) ^ (p_instance.x[3] << 16);
        p_dest[i + 5] = p_src[i + 5] ^ p_instance.x[2] ^
            (p_instance.x[7] >> 16) ^ (p_instance.x[5] << 16);
        p_dest[i + 6] = p_src[i + 6] ^ p_instance.x[4] ^
            (p_instance.x[1] >> 16) ^ (p_instance.x[7] << 16);
        p_dest[i + 7] = p_src[i + 7] ^ p_instance.x[6] ^
            (p_instance.x[3] >> 16) ^ (p_instance.x[1] << 16);
        p_dest[i + 8] = p_src[i + 8] ^ p_instance.x[0] ^
            (p_instance.x[5] >> 16) ^ (p_instance.x[3] << 16);
        p_dest[i + 9] = p_src[i + 9] ^ p_instance.x[2] ^
            (p_instance.x[7] >> 16) ^ (p_instance.x[5] << 16);
        p_dest[i + 10] = p_src[i + 10] ^ p_instance.x[4] ^
            (p_instance.x[1] >> 16) ^ (p_instance.x[7] << 16);
        p_dest[i + 11] = p_src[i + 11] ^ p_instance.x[6] ^
            (p_instance.x[3] >> 16) ^ (p_instance.x[1] << 16);
        p_dest[i + 12] = p_src[i + 12] ^ p_instance.x[0] ^
            (p_instance.x[5] >> 16) ^ (p_instance.x[3] << 16);
        p_dest[i + 13] = p_src[i + 13] ^ p_instance.x[2] ^
            (p_instance.x[7] >> 16) ^ (p_instance.x[5] << 16);
        p_dest[i + 14] = p_src[i + 14] ^ p_instance.x[4] ^
            (p_instance.x[1] >> 16) ^ (p_instance.x[7] << 16);
        p_dest[i + 15] = p_src[i + 15] ^ p_instance.x[6] ^
            (p_instance.x[3] >> 16) ^ (p_instance.x[1] << 16);
    }

    // Return success
    return 0;
}
