%%

function success = rabbit_key_setup(p_instance, p_key)
    success = 0;
    key_size = numel(p_key);

    if key_size ~= 16
        error('Key size must be 16 bytes.');
    end

    for i = 0:3
        p_instance.x(i+4) = rabbit_le32_to_uint32(p_key(i*4+1:i*4+4));
    end

    for i = 0:3
        p_instance.x(i) = bitxor(p_instance.x(i), p_instance.x(i+4));
    end

    if key_size == 16
        p_instance.x(6) = bitxor(p_instance.x(6), 0x01234567);
    end

    for i = 0:7
        p_instance.c(i) = 0;
    end

    p_instance.carry = 0;
    success = 1;
end

function success = rabbit_iv_setup(p_master_instance, p_instance, p_iv)
    success = 0;
    iv_size = numel(p_iv);

    if iv_size ~= 8
        error('IV size must be 8 bytes.');
    end

    for i = 0:3
        p_instance.x(i) = rabbit_le32_to_uint32(p_iv(i*4+1:i*4+4));
        p_instance.c(i) = bitxor(p_instance.c(i), p_instance.x(i));
    end

    for i = 4:7
        p_instance.x(i) = p_master_instance.x(i);
        p_instance.c(i) = bitxor(p_instance.c(i), p_instance.x(i));
    end

    p_instance.carry = p_master_instance.carry;
    success = 1;
end

function p_dest = rabbit_cipher(p_instance, p_src)
    p_dest = zeros(size(p_src), 'uint8');
    data_size = numel(p_src);

    if mod(data_size, 16) ~= 0
        error('Data size must be a multiple of 16 bytes.');
    end

    for i = 1:16:data_size
        rabbit_next_state(p_instance);
        p_dest(i:i+15) = bitxor(p_src(i:i+15), typecast([p_instance.x(1) bitshift(p_instance.x(5), -16) bitshift(p_instance.x(3), 16)], 'uint8'));
    end
end

function p_dest = rabbit_prng(p_instance, data_size)
    p_dest = zeros(data_size, 'uint8');

    for i = 1:16:data_size
        rabbit_next_state(p_instance);
        p_dest(i:i+15) = typecast([p_instance.x(1) bitshift(p_instance.x(5), -16) bitshift(p_instance.x(3), 16)], 'uint8');
    end
end

function rabbit_next_state(p_instance)
    g = zeros(8, 1, 'uint32');
    c_old = p_instance.c;

    p_instance.c(1) = p_instance.c(1) + uint32(0x4D34D34D) + p_instance.carry;
    p_instance.c(2) = p_instance.c(2) + uint32(0xD34D34D3) + (p_instance.c(1) < c_old(1));
    p_instance.c(3) = p_instance.c(3) + uint32(0x34D34D34) + (p_instance.c(2) < c_old(2));
    p_instance.c(4) = p_instance.c(4) + uint32(0x4D34D34D) + (p_instance.c(3) < c_old(3));
    p_instance.c(5) = p_instance.c(5) + uint32(0xD34D34D3) + (p_instance.c(4) < c_old(4));
    p_instance.c(6) = p_instance.c(6) + uint32(0x34D34D34) + (p_instance.c(5) < c_old(5));
    p_instance.c(7) = p_instance.c(7) + uint32(0x4D34D34D) + (p_instance.c(6) < c_old(6));
    p_instance.c(8) = p_instance.c(8) + uint32(0xD34D34D3) + (p_instance.c(7) < c_old(7));
    p_instance.carry = (p_instance.c(8) < c_old(8));

    g(0+1) = rabbit_g_func(p_instance.x(0+1));
    g(1+1) = rabbit_g_func(p_instance.x(1+1));
    g(2+1) = rabbit_g_func(p_instance.x(2+1));
    g(3+1) = rabbit_g_func(p_instance.x(3+1));
    g(4+1) = rabbit_g_func(p_instance.x(4+1));
    g(5+1) = rabbit_g_func(p_instance.x(5+1));
    g(6+1) = rabbit_g_func(p_instance.x(6+1));
    g(7+1) = rabbit_g_func(p_instance.x(7+1));

    p_instance.x(0+1) = g(0+1) + rabbit_rotl(g(7+1), 16) + rabbit_rotl(g(6+1), 16);
    p_instance.x(1+1) = g(1+1) + rabbit_rotl(g(0+1), 8) + g(7+1);
    p_instance.x(2+1) = g(2+1) + rabbit_rotl(g(1+1), 16) + rabbit_rotl(g(0+1), 16);
    p_instance.x(3+1) = g(3+1) + rabbit_rotl(g(2+1), 8) + g(1+1);
    p_instance.x(4+1) = g(4+1) + rabbit_rotl(g(3+1), 16) + rabbit_rotl(g(2+1), 16);
    p_instance.x(5+1) = g(5+1) + rabbit_rotl(g(4+1), 8) + g(3+1);
    p_instance.x(6+1) = g(6+1) + rabbit_rotl(g(5+1), 16) + rabbit_rotl(g(4+1), 16);
    p_instance.x(7+1) = g(7+1) + rabbit_rotl(g(6+1), 8) + g(5+1);
end

function result = rabbit_g_func(x)
    a = bitshift(x, 16);
    b = bitshift(x, -16);
    c = bitshift(x, 16);
    d = bitshift(x, -16);

    result = rabbit_g_func_a(a) + rabbit_g_func_b(b) + rabbit_g_func_c(c) + rabbit_g_func_d(d);
end

function result = rabbit_g_func_a(x)
    x = bitand(x, uint32(0xFF00FF00));
    x = bitor(x, bitshift(x, -8));
    result = bitxor(x, bitshift(x, -4));
end

function result = rabbit_g_func_b(x)
    x = bitand(x, uint32(0x00FF00FF));
    x = bitor(x, bitshift(x, 8));
    result = bitxor(x, bitshift(x, 4));
end

function result = rabbit_g_func_c(x)
    result = bitxor(x, bitshift(x, 2));
    result = bitxor(result, bitshift(result, 1));
end

function result = rabbit_g_func_d(x)
    result = bitxor(x, bitshift(x, 1));
    result = bitxor(result, bitshift(result, 2));
end

function result = rabbit_rotl(x, n)
    result = bitshift(x, n) + bitshift(x, n - 32);
end


%%
% function p_dest = rabbit_cipher(p_instance, p_src)
%   p_dest = zeros(size(p_src), 'uint8');
%   data_size = numel(p_src);

%   if mod(data_size, 16) ~= 0
%     error('Data size must be a multiple of 16 bytes.');
%   end

%   for i = 1:16:data_size
%     rabbit_next_state(p_instance);
%     p_dest(i:i+15) = bitxor(p_src(i:i+15), typecast([p_instance.x(1) bitshift(p_instance.x(5), -16) bitshift(p_instance.x(3), 16)], 'uint8'));
%   end
% end

% function rabbit_next_state(p_instance)
%   g = zeros(8, 1, 'uint32');
%   c_old = p_instance.c;

%   p_instance.c(1) = p_instance.c(1) + uint32(0x4D34D34D) + p_instance.carry;
%   p_instance.c(2) = p_instance.c(2) + uint32(0xD34D34D3) + (p_instance.c(1) < c_old(1));
%   p_instance.c(3) = p_instance.c(3) + uint32(0x34D34D34) + (p_instance.c(2) < c_old(2));
%   p_instance.c(4) = p_instance.c(4) + uint32(0x4D34D34D) + (p_instance.c(3) < c_old(3));
%   p_instance.c(5) = p_instance.c(5) + uint32(0xD34D34D3) + (p_instance.c(4) < c_old(4));
%   p_instance.c(6) = p_instance.c(6) + uint32(0x34D34D34) + (p_instance.c(5) < c_old(5));
%   p_instance.c(7) = p_instance.c(7) + uint32(0x4D34D34D) + (p_instance.c(6) < c_old(6));
%   p_instance.carry = (p_instance.c(7) < c_old(7));

%   for i = 1:8
%     g(i) = rabbit_g_func(p_instance.x(i) + p_instance.c(i));
%   end

%   p_instance.x(1) = g(1) + rabbit_rotl(g(8), 16) + rabbit_rotl(g(7), 16);
%   p_instance.x(2) = g(2) + rabbit_rotl(g(1), 8) + g(8);
%   p_instance.x(3) = g(3) + rabbit_rotl(g(2), 16) + rabbit_rotl(g(1), 16);
%   p_instance.x(4) = g(4) + rabbit_rotl(g(3), 8) + g(2);
%   p_instance.x(5) = g(5) + rabbit_rotl(g(4), 16) + rabbit_rotl(g(3), 16);
%   p_instance.x(6) = g(6) + rabbit_rotl(g(5), 8) + g(4);
%   p_instance.x(7) = g(7) + rabbit_rotl(g(6), 16) + rabbit_rotl(g(5), 16);
%   p_instance.x(8) = g(8) + rabbit_rotl(g(7), 8) + g(6);
% end

% function z = rabbit_g_func(x)
%   a = bitand(x, 0xFFFF);
%   b = bitand(bitshift(x, -16), 0xFFFF);
%   z = rabbit_mod_0x100000000(uint32(a * b) + bitshift(a, 16) + bitshift(b, 16));
% end

% function z = rabbit_mod_0x100000000(x)
%   z = uint32(mod(double(x), 2^32));
% end

% function z = rabbit_rotl(x, n)
%   z = bitor(bitshift(x, n), bitshift(x, n - 32));
% end

