%%

key1  =  [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00];

out1  =  [0x02, 0xF7, 0x4A, 0x1C, 0x26, 0x45, 0x6B, 0xF5, 0xEC, 0xD6, 0xA5, 0x36, 0xF0, 0x54, 0x57, 0xB1,
          0xA7, 0x8A, 0xC6, 0x89, 0x47, 0x6C, 0x69, 0x7B, 0x39, 0x0C, 0x9C, 0xC5, 0x15, 0xD8, 0xE8, 0x88,
          0xEF, 0x9A, 0x69, 0x71, 0x8B, 0x82, 0x49, 0xA1, 0xA7, 0x3C, 0x5A, 0x6E, 0x5B, 0x90, 0x45, 0x95];

tester(key1, out1)

% Type declarations
cc_byte = uint8;
cc_uint32 = uint32;

% Structure to store the instance data (internal state)
rabbit_instance = struct('x', zeros(1, 8, 'uint32'), ...
                         'c', zeros(1, 8, 'uint32'), ...
                         'carry', uint32(0));

% Testing function
function tester(key, output)
    % Set up the instance
    instance = rabbit_instance;
    rabbit_key_setup(instance, key, numel(key));
    
    % Encrypt the plaintext
    ciphertext = zeros(size(output), 'uint8');
    rabbit_cipher(instance, output, ciphertext, numel(output));
    
    % Compare the ciphertext with the expected output
    if isequal(ciphertext, output)
        disp('Encryption successful!');
    else
        disp('Encryption failed!');
    end
end

% Function: rabbit_key_setup
function status = rabbit_key_setup(p_instance, p_key, key_size)
    % Check input arguments
    if key_size ~= 16 && key_size ~= 20 && key_size ~= 24
        status = -1;  % Error: Invalid key size
        return;
    end
    
    % Initialize the instance data
    p_instance.x = zeros(1, 8, 'uint32');
    p_instance.c = zeros(1, 8, 'uint32');
    p_instance.carry = uint32(0);
    
    % Key setup
    k = zeros(1, 8, 'uint32');
    for i = 1:4
        k(i) = typecast(p_key((4*i-3):(4*i)), 'uint32');
        k(i+4) = k(i);
    end
    
    % Initialize the cipher state
    p_instance.x(0+1) = bitxor(k(0+1), typecast(p_key(17:20), 'uint32'));
    p_instance.x(2+1) = bitxor(k(1+1), typecast(p_key(17:20), 'uint32'));
    p_instance.x(4+1) = bitxor(k(2+1), typecast(p_key(17:20), 'uint32'));
    p_instance.x(6+1) = bitxor(k(3+1), typecast(p_key(17:20), 'uint32'));
    p_instance.x(1+1) = bitxor(bitshift(k(3+1), -16, 'uint32'), bitshift(k(2+1), 16, 'uint32'));
    p_instance.x(3+1) = bitxor(bitshift(k(0+1), -16, 'uint32'), bitshift(k(3+1), 16, 'uint32'));
    p_instance.x(5+1) = bitxor(bitshift(k(1+1), -16, 'uint32'), bitshift(k(0+1), 16, 'uint32'));
    p_instance.x(7+1) = bitxor(bitshift(k(2+1), -16, 'uint32'), bitshift(k(1+1), 16, 'uint32'));
    
    % Generate initial state values
    p_instance.c(0+1) = bitrotate(bitxor(k(2+1), k(0+1)), 16, 'uint32');
    p_instance.c(2+1) = bitrotate(k(0+1), 16, 'uint32');
    p_instance.c(4+1) = bitrotate(bitxor(k(2+1), k(1+1)), 16, 'uint32');
    p_instance.c(6+1) = bitrotate(k(1+1), 16, 'uint32');
    p_instance.c(1+1) = bitrotate(bitxor(k(3+1), k(2+1)), 16, 'uint32');
    p_instance.c(3+1) = bitrotate(k(2+1), 16, 'uint32');
    p_instance.c(5+1) = bitrotate(bitxor(k(3+1), k(0+1)), 16, 'uint32');
    p_instance.c(7+1) = bitrotate(k(0+1), 16, 'uint32');
    
    p_instance.carry = uint32(0);
    
    status = 0;  % Success
end

% Function: rabbit_iv_setup
function status = rabbit_iv_setup(p_master_instance, p_instance, p_iv, iv_size)
    % Check input arguments
    if iv_size ~= 8
        status = -1;  % Error: Invalid IV size
        return;
    end
    
    % Copy the master instance data to the working instance
    p_instance.x = p_master_instance.x;
    p_instance.c = p_master_instance.c;
    p_instance.carry = p_master_instance.carry;
    
    % IV setup
    p_instance.x(0+1) = bitxor(p_instance.x(0+1), typecast(p_iv(1:4), 'uint32'));
    p_instance.x(2+1) = bitxor(p_instance.x(2+1), typecast(p_iv(1:4), 'uint32'));
    p_instance.x(4+1) = bitxor(p_instance.x(4+1), typecast(p_iv(5:8), 'uint32'));
    p_instance.x(6+1) = bitxor(p_instance.x(6+1), typecast(p_iv(5:8), 'uint32'));
    p_instance.x(1+1) = bitxor(bitshift(p_instance.x(1+1), -16, 'uint32'), bitshift(p_instance.x(0+1), 16, 'uint32'));
    p_instance.x(3+1) = bitxor(bitshift(p_instance.x(3+1), -16, 'uint32'), bitshift(p_instance.x(2+1), 16, 'uint32'));
    p_instance.x(5+1) = bitxor(bitshift(p_instance.x(5+1), -16, 'uint32'), bitshift(p_instance.x(4+1), 16, 'uint32'));
    p_instance.x(7+1) = bitxor(bitshift(p_instance.x(7+1), -16, 'uint32'), bitshift(p_instance.x(6+1), 16, 'uint32'));
    
    % Generate initial state values
    p_instance.c(0+1) = bitrotate(bitxor(p_instance.c(2+1), p_instance.c(0+1)), 16, 'uint32');
    p_instance.c(2+1) = bitrotate(p_instance.c(0+1), 16, 'uint32');
    p_instance.c(4+1) = bitrotate(bitxor(p_instance.c(2+1), p_instance.c(1+1)), 16, 'uint32');
    p_instance.c(6+1) = bitrotate(p_instance.c(1+1), 16, 'uint32');
    p_instance.c(1+1) = bitrotate(bitxor(p_instance.c(3+1), p_instance.c(2+1)), 16, 'uint32');
    p_instance.c(3+1) = bitrotate(p_instance.c(2+1), 16, 'uint32');
    p_instance.c(5+1) = bitrotate(bitxor(p_instance.c(3+1), p_instance.c(0+1)), 16, 'uint32');
    p_instance.c(7+1) = bitrotate(p_instance.c(0+1), 16, 'uint32');
    
    p_instance.carry = uint32(0);
    
    status = 0;  % Success
end

% Function: rabbit_cipher
function status = rabbit_cipher(p_instance, p_src, p_dest, data_size)
    % Check input arguments
    if mod(data_size, 16) ~= 0
        status = -1;  % Error: Invalid data size
        return;
    end
    
    % Iterate over the data blocks
    num_blocks = data_size / 16;
    for i = 1:num_blocks
        % Generate the keystream
        ks = rabbit_keystream(p_instance);
        
        % Encrypt the data block
        block = typecast(p_src(((i-1)*16+1):(i*16)), 'uint32');
        encrypted = bitxor(block, ks);
        
        % Store the encrypted block
        p_dest(((i-1)*16+1):(i*16)) = typecast(encrypted, 'uint8');
    end
    
    status = 0;  % Success
end

% Function: rabbit_keystream
function ks = rabbit_keystream(p_instance)
    % Update the instance state
    for i = 0:7
        p_instance.c(i+1) = bitadd(p_instance.c(i+1), p_instance.x(i+1), 'uint32');
    end
    
    % Generate the keystream
    ks = zeros(1, 16, 'uint8');
    for i = 0:7
        ks(i*4+1) = typecast(bitand(p_instance.x(i+1), 255, 'uint32'), 'uint8');
        ks(i*4+2) = typecast(bitand(bitshift(p_instance.x(i+1), -8, 'uint32'), 255, 'uint32'), 'uint8');
        ks(i*4+3) = typecast(bitand(bitshift(p_instance.x(i+1), -16, 'uint32'), 255, 'uint32'), 'uint8');
        ks(i*4+4) = typecast(bitand(bitshift(p_instance.x(i+1), -24, 'uint32'), 255, 'uint32'), 'uint8');
    end
    
    % Update the instance state again
    for i = 0:7
        temp = p_instance.x(i+1);
        p_instance.x(i+1) = bitadd(p_instance.x(i+1), p_instance.c(i+1), 'uint32');
        p_instance.c(i+1) = bitxor(p_instance.c(i+1), temp);
    end
    
    % Handle carry propagation
    p_instance.carry = bitshift(bitxor(p_instance.carry, p_instance.c(0+1)), -31, 'uint32');
    for i = 0:6
        p_instance.c(i+1) = bitxor(p_instance.c(i+1), bitshift(p_instance.c(i+2), -1, 'uint32'));
    end
    p_instance.c(7+1) = bitxor(p_instance.c(7+1), bitshift(p_instance.carry, -1, 'uint32'));
end

% Function: bitadd (32-bit addition with carry)
function result = bitadd(a, b, datatype)
    result = bitxor(a, b, datatype);
    carry = bitand(a, b, datatype);
    while carry ~= 0
        carry = bitshift(carry, 1, datatype);
        temp = result;
        result = bitxor(result, carry, datatype);
        carry = bitand(temp, carry, datatype);
    end
end

% Function: bitrotate (bit rotation)
function result = bitrotate(value, shift, datatype)
    result = bitor(bitshift(value, shift, datatype), bitshift(value, shift - 32, datatype));
end

%%
