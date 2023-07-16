%%
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
