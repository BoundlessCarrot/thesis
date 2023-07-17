%%
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
%%
