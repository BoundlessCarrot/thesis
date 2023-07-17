%%
function main()
    % Main function
    
    % Define key, IV, and expected result blocks
    key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, ...
           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    
    iv = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    
    result_cipher = [0xED, 0xB7, 0x23, 0x30, 0x10, 0xC7, 0x1B, 0x11, ...
                     0x29, 0x71, 0x16, 0x24, 0xDB, 0x9F, 0xAD, 0x17];
    
    result_prng = [0xA3, 0xB8, 0x99, 0x89, 0x48, 0xA9, 0x0C, 0xE4, ...
                   0x4E, 0xAA, 0x6B, 0x5B, 0x86, 0xBD, 0x82, 0xCA];
    
    % Test key setup and cipher
    success_cipher = test_key_setup_and_cipher(key, result_cipher);
    fprintf('Key setup and cipher test: %d\n', success_cipher);
    
    % Test key setup, IV setup, and cipher
    success_iv_cipher = test_key_setup_and_iv_setup_and_cipher(key, iv, result_cipher);
    fprintf('Key setup, IV setup, and cipher test: %d\n', success_iv_cipher);
    
    % Test key setup and PRNG
    success_prng = test_key_setup_and_prng(key, result_prng);
    fprintf('Key setup and PRNG test: %d\n', success_prng);
    
    % Test key setup, IV setup, and PRNG
    success_iv_prng = test_key_setup_and_iv_setup_and_prng(key, iv, result_prng);
    fprintf('Key setup, IV setup, and PRNG test: %d\n', success_iv_prng);
end

function clear(p_dest, data_size)
    % Clear the block
    for i = 1:data_size
        p_dest(i) = 0;
    end
end

function equal = test_if_equal(p_src1, p_src2, data_size)
    % Test if two blocks are equal
    % Inputs:
    %   - p_src1: First block to compare
    %   - p_src2: Second block to compare
    %   - data_size: Size of the blocks
    % Output:
    %   - equal: 1 if blocks are equal, 0 otherwise
    
    % Test the block
    for i = 1:data_size
        if (p_src1(i) ~= p_src2(i))
            equal = 0;
            return;
        end
    end
    equal = 1;
end

function success = test_key_setup_and_cipher(p_key, p_res)
    % Test key setup and cipher functions
    % Inputs:
    %   - p_key: Key block
    %   - p_res: Expected result block after cipher
    % Output:
    %   - success: 1 if test passed, 0 otherwise
    
    % Initialize Rabbit instance
    obj = RabbitContainer();
    r_inst = obj.rabbit_instance();
    
    % Create buffer for encryption
    buffer = zeros(1, 48, 'uint8');
    
    % Perform key setup
    obj.rabbit_key_setup(r_inst, p_key, 16);
    
    % Clear the buffer
    clear(buffer, 48);
    
    % Encrypt the buffer
    obj.rabbit_cipher(r_inst, buffer, buffer, 48);
    
    % Test if buffer matches expected result
    success = test_if_equal(buffer, p_res, 48) == 0;
end

function success = test_key_setup_and_iv_setup_and_cipher(p_key, p_iv, p_res)
    % Test key setup, IV setup, and cipher functions
    % Inputs:
    %   - p_key: Key block
    %   - p_iv: IV block
    %   - p_res: Expected result block after cipher
    % Output:
    %   - success: 1 if test passed, 0 otherwise
    
    % Initialize Rabbit instances
    obj1 = RabbitContainer();
    obj2 = RabbitContainer();
    r_master_inst = obj1.rabbit_instance();
    r_inst = obj2.rabbit_instance();
    
    % Create buffer for encryption
    buffer = zeros(1, 48, 'uint8');
    
    % Perform key setup using master instance
    obj1.rabbit_key_setup(r_master_inst, p_key, 16);
    
    % Perform IV setup using master and working instances
    obj2.rabbit_iv_setup(r_master_inst, r_inst, p_iv, 8);
    
    % Clear the buffer
    clear(buffer, 48);
    
    % Encrypt the buffer
    obj2.rabbit_cipher(r_inst, buffer, buffer, 48);
    
    % Test if buffer matches expected result
    success = test_if_equal(buffer, p_res, 48) == 0;
end

function success = test_key_setup_and_prng(p_key, p_res)
    % Test key setup and PRNG (pseudo-random number generation) functions
    % Inputs:
    %   - p_key: Key block
    %   - p_res: Expected result block from PRNG
    % Output:
    %   - success: 1 if test passed, 0 otherwise
    
    % Initialize Rabbit instance
    obj = RabbitContainer();
    r_inst = obj.rabbit_instance();
    
    % Create buffer for PRNG output
    buffer = zeros(1, 48, 'uint8');
    
    % Perform key setup
    obj.rabbit_key_setup(r_inst, p_key, 16);
    
    % Generate pseudo-random numbers
    rabbit_prng(r_inst, buffer, 48);
    
    % Test if buffer matches expected result
    success = test_if_equal(buffer, p_res, 48) == 0;
end

function success = test_key_setup_and_iv_setup_and_prng(p_key, p_iv, p_res)
    % Test key setup, IV setup, and PRNG (pseudo-random number generation) functions
    % Inputs:
    %   - p_key: Key block
    %   - p_iv: IV block
    %   - p_res: Expected result block from PRNG
    % Output:
    %   - success: 1 if test passed, 0 otherwise
    
    % Initialize Rabbit instances
    obj1 = RabbitContainer();
    obj2 = RabbitContainer();
    r_master_inst = obj1.rabbit_instance();
    r_inst = obj2.rabbit_instance();
    
    % Create buffer for PRNG output
    buffer = zeros(1, 48, 'uint8');
    
    % Perform key setup using master instance
    obj1.rabbit_key_setup(r_master_inst, p_key, 16);
    
    % Perform IV setup using master and working instances
    obj1.rabbit_iv_setup(r_master_inst, r_inst, p_iv, 8);
    
    % Generate pseudo-random numbers
    rabbit_prng(r_inst, buffer, 48);
    % buffer = rand(1, 48, 'uint8');

    % Test if buffer matches expected result
    success = test_if_equal(buffer, p_res, 48) == 0;
end
%%
