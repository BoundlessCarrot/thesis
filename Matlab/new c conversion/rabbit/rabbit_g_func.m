%%
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

%%
