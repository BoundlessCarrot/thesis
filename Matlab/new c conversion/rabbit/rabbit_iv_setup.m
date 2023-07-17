%%
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
%%
