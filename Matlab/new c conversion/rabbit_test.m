%%
% rabbit_test.m

% Set the key and IV values
key = uint32([0x01234567, 0x89abcdef]);
iv = uint32([0x01234567, 0x89abcdef]);

% Initialize the Rabbit cipher
state = rabbit_init(key, iv);

% Generate 10 output blocks
for i = 1:10
    % Generate the next block of keystream
    keystream = rabbit_generate_keystream(state);
    
    % Print the generated keystream
    fprintf('Keystream block %d: 0x%08x 0x%08x\n', i, keystream(1), keystream(2));
end
%%
