%%
% File name: rabbit.m
% ------------------------------------------------------------------------
% MATLAB implementation of the RABBIT stream cipher.
%
% For further documentation, see "Rabbit Stream Cipher, Algorithm
% Specification" which can be found at http://www.cryptico.com/.
%
% This source code is for little-endian processors (e.g. x86).
% ------------------------------------------------------------------------
% Cryptico ApS. All rights reserved.
%
% YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.
%
% This software is developed by Cryptico ApS and/or its suppliers. It is
% free for commercial and non-commercial use.
%
% Cryptico ApS shall not in any way be liable for any use or export/import
% of this software. The software is provided "as is" without any express or
% implied warranty.
%
% Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption" are
% either trademarks or registered trademarks of Cryptico ApS.
% ------------------------------------------------------------------------

function p_dest = rabbit(p_key, p_iv, p_src)
    % Initialize the cipher instance
    instance = rabbit_key_setup(p_key);
    
    % Set the IV
    instance = rabbit_iv_setup(instance, p_iv);
    
    % Encrypt or decrypt data
    p_dest = rabbit_cipher(instance, p_src);
end

function instance = rabbit_key_setup(p_key)
    % Generate four subkeys
    k0 = typecast(p_key(1:4), 'uint32');
    k1 = typecast(p_key(5:8), 'uint32');
    k2 = typecast(p_key(9:12), 'uint32');
    k3 = typecast(p_key(13:16), 'uint32');
    
    % Generate initial state variables
    instance.x = zeros(1, 8, 'uint32');
    instance.x(1) = k0;
    instance.x(3) = k1;
    instance.x(5) = k2;
    instance.x(7) = k3;
    instance.x(2) = bitshift(k3, 16) + bitshift(k2, -16);
    instance.x(4) = bitshift(k0, 16) + bitshift(k3, -16);
    instance.x(6) = bitshift(k1, 16) + bitshift(k0, -16);
    instance.x(8) = bitshift(k2, 16) + bitshift(k1, -16);
    
    % Generate initial counter values
    instance.c = zeros(1, 8, 'uint32');
    instance.c(1) = rabbit_rotl(k2, 16);
    instance.c(3) = rabbit_rotl(k3, 16);
    instance.c(5) = rabbit_rotl(k0, 16);
    instance.c(7) = rabbit_rotl(k1, 16);
    instance.c(2) = bitand(k0, hex2dec('FFFF0000')) + bitand(k1, hex2dec('FFFF'));
    instance.c(4) = bitand(k1, hex2dec('FFFF0000')) + bitand(k2, hex2dec('FFFF'));
    instance.c(6) = bitand(k2, hex2dec('FFFF0000')) + bitand(k3, hex2dec('FFFF'));
    instance.c(8) = bitand(k3, hex2dec('FFFF0000')) + bitand(k0, hex2dec('FFFF'));
    
    % Clear carry bit
    instance.carry = uint32(0);
    
    % Iterate the system four times
    for i = 1:4
        instance = rabbit_next_state(instance);
    end
end

function instance = rabbit_iv_setup(master_instance, instance, p_iv)
    % Generate four subvectors
    i0 = typecast(p_iv(1:4), 'uint32');
    i2 = typecast(p_iv(5:8), 'uint32');
    i1 = bitshift(i0, -16) + bitand(i2, hex2dec('FFFF0000'));
    i3 = bitshift(i2, -16) + bitand(i0, hex2dec('0000FFFF'));
    
    % Modify counter values
    instance.c = master_instance.c;
    instance.c(1:2:7) = bitxor(instance.c(1:2:7), i0);
    instance.c(2:2:8) = bitxor(instance.c(2:2:8), i1);
    
    % Copy internal state values
    instance.x = master_instance.x;
    instance.carry = master_instance.carry;
    
    % Iterate the system four times
    for i = 1:4
        instance = rabbit_next_state(instance);
    end
end

function instance = rabbit_next_state(instance)
    % Save old counter values
    c_old = instance.c;
    
    % Calculate new counter values
    instance.c(1) = instance.c(1) + uint32(hex2dec('4D34D34D')) + instance.carry;
    instance.c(2) = instance.c(2) + uint32(hex2dec('D34D34D3')) + (instance.c(1) < c_old(1));
    instance.c(3) = instance.c(3) + uint32(hex2dec('34D34D34')) + (instance.c(2) < c_old(2));
    instance.c(4) = instance.c(4) + uint32(hex2dec('4D34D34D')) + (instance.c(3) < c_old(3));
    instance.c(5) = instance.c(5) + uint32(hex2dec('D34D34D3')) + (instance.c(4) < c_old(4));
    instance.c(6) = instance.c(6) + uint32(hex2dec('34D34D34')) + (instance.c(5) < c_old(5));
    instance.c(7) = instance.c(7) + uint32(hex2dec('4D34D34D')) + (instance.c(6) < c_old(6));
    instance.c(8) = instance.c(8) + uint32(hex2dec('D34D34D3')) + (instance.c(7) < c_old(7));
    instance.carry = (instance.c(8) < c_old(8));
   
    % Calculate the g-functions
    g = zeros(1, 8, 'uint32');
    for i = 1:8
        g(i) = rabbit_g_func(instance.x(i) + instance.c(i));
    end
    
    % Calculate new state values
    instance.x(1) = g(1) + rabbit_rotl(g(8), 16) + rabbit_rotl(g(7), 16);
    instance.x(2) = g(2) + rabbit_rotl(g(1), 8) + g(8);
    instance.x(3) = g(3) + rabbit_rotl(g(2), 16) + rabbit_rotl(g(1), 16);
    instance.x(4) = g(4) + rabbit_rotl(g(3), 8) + g(2);
    instance.x(5) = g(5) + rabbit_rotl(g(4), 16) + rabbit_rotl(g(3), 16);
    instance.x(6) = g(6) + rabbit_rotl(g(5), 8) + g(4);
    instance.x(7) = g(7) + rabbit_rotl(g(6), 16) + rabbit_rotl(g(5), 16);
    instance.x(8) = g(8) + rabbit_rotl(g(7), 8) + g(6);
end

function result = rabbit_rotl(x, rot)
    result = bitshift(x, rot) + bitshift(x, rot - 32);
end

function result = rabbit_g_func(x)
    % Temporary variables
    a = bitand(x, hex2dec('FFFF'));
    b = bitshift(x, -16);
    
    % Calculate high and low result of squaring
    h = bitshift(bitshift(a * a, -17) + a * b, -15) + b * b;
    l = x * x;
    
    % Return high XOR low
    result = bitxor(h, l);
end

function p_dest = rabbit_cipher(instance, p_src)
    % Initialize the destination data
    p_dest = zeros(size(p_src), 'uint8');
    
    % Encrypt or decrypt data
    for i = 1:16:numel(p_src)
        % Iterate the system
        instance = rabbit_next_state(instance);

        % Encrypt 16 bytes of data
        p_dest(i:i+15) = typecast(bitxor(typecast(p_src(i:i+15), 'uint32'), ...
            instance.x(1:8) + bitshift(instance.x(5), -16) + bitshift(instance.x(3), 16)), 'uint8');
    end
end
%%
