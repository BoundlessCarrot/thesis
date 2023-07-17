%%
% rabbitTests.m

% Define the test cases
testCases = [
    struct('key', uint32([0x01234567, 0x89abcdef]), ...
           'iv', uint32([0x01234567, 0x89abcdef]), ...
           'out', uint32([0x4a4f6e20, 0x2d4e7765])),
    
    struct('key', uint32([0xfedcba98, 0x76543210]), ...
           'iv', uint32([0xfedcba98, 0x76543210]), ...
           'out', uint32([0xb3c1cc7a, 0x2a4e443e])),
    
    struct('key', uint32([0xdeadbeef, 0xdeadbeef]), ...
           'iv', uint32([0xdeadbeef, 0xdeadbeef]), ...
           'out', uint32([0x67a7ef8a, 0x9e8e7b8a])),
    
    struct('key', uint32([0x01234567, 0x89abcdef]), ...
           'iv', uint32([0xfedcba98, 0x76543210]), ...
           'out', uint32([0xc61e6df6, 0x5c564b56])),
    
    struct('key', uint32([0xfedcba98, 0x76543210]), ...
           'iv', uint32([0x01234567, 0x89abcdef]), ...
           'out', uint32([0x78e37758, 0x10d2edbf])),
    
    struct('key', uint32([0xdeadbeef, 0xdeadbeef]), ...
           'iv', uint32([0xdeadbeef, 0xdeadbeef]), ...
           'out', uint32([0x080c3ae3, 0x68af1a6b]))
];

% Run the tests
for i = 1:length(testCases)
    testCase = testCases(i);
    
    % Call the Rabbit cipher implementation with the test case parameters
    output = rabbit_cipher(testCase.key, testCase.iv);
    
    % Check if the output matches the expected result
    if isequal(output, testCase.out)
        fprintf('Test case %d passed.\n', i);
    else
        fprintf('Test case %d failed.\n', i);
    end
end
%%
