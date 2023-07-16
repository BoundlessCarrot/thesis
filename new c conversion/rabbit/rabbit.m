%%
function p_dest = rabbit(p_key, p_iv, p_src)
    % Initialize the cipher instance
    instance = rabbit_key_setup(p_key);
    
    % Set the IV
    instance = rabbit_iv_setup(instance, p_iv);
    
    % Encrypt or decrypt data
    p_dest = rabbit_cipher(instance, p_src);
end
%%
