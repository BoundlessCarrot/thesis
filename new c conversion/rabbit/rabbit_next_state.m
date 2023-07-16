%%
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

%%
