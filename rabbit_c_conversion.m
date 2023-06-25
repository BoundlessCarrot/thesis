%%



tester(key1, out1)

classdef RabbitContainer
  methods

    function rabbit_instance = rabbit_instance
      rabbit_instance = struct( ...
        'x', zeros(1, 8, 'uint32'), ...
        'c', zeros(1, 8, 'uint32'), ...
        'carry', uint32(0) ...
        );
    end

    % Function: rabbit_key_setup
    function status = rabbit_key_setup(p_instance, p_key, key_size)
      % Check input arguments
      if key_size ~= 16
        status = -1;  % Error: Invalid key size
        return;
      end

      % Preallocate the k array
      % k = zeros(numel(p_key) / 4, numel(p_key) / 4, 'uint32');
      k = reshape(uint32(p_key), numel(p_key) / 4, numel(p_key) / 4);

      % Extract the key words
      % for i = 1:numel(k)
      %     disp(k(i, :));
      %     disp(typecast(p_key((4*i-3),(4*i)), 'uint32'));
      %     k(i, :) = typecast(p_key((2*i-1):(2*i)), 'uint32');
      % end

      % Key setup
      p_instance.x(1) = bitxor(k(1), 0x9E3779B9);
      p_instance.x(2) = bitxor(k(2), 0x3C6EF372);
      p_instance.x(3) = bitxor(k(3), 0xDA66D50E);
      p_instance.x(4) = bitxor(k(4), 0x0B6B27A6);
      p_instance.x(5) = bitxor(k(5), bitrotate(k(3), -16, 'uint32'));
      p_instance.x(6) = bitxor(k(2), bitrotate(k(4), 16, 'uint32'));
      p_instance.x(7) = bitxor(k(3), bitrotate(k(1), -16, 'uint32'));
      p_instance.x(8) = bitxor(k(4), bitrotate(k(2), 16, 'uint32'));

      p_instance.c(0+1) = bitrotate(k(2+1), -16, 'uint32');
      p_instance.c(1+1) = bitrotate(k(0+1), 16, 'uint32');
      p_instance.c(2+1) = bitrotate(k(3+1), -16, 'uint32');
      p_instance.c(3+1) = bitrotate(k(1+1), 16, 'uint32');
      p_instance.c(4+1) = bitrotate(k(2+1), -16, 'uint32');
      p_instance.c(5+1) = bitrotate(k(0+1), 16, 'uint32');
      p_instance.c(6+1) = bitrotate(k(3+1), -16, 'uint32');
      p_instance.c(7+1) = bitrotate(k(1+1), 16, 'uint32');

      p_instance.carry = 0;
      status = 0;  % Success
    end

    % Function: rabbit_iv_setup
    function status = rabbit_iv_setup(p_master_instance, p_instance, p_iv, iv_size)
      % Check input arguments
      if iv_size ~= 8
        status = -1;  % Error: Invalid IV size
        return;
      end

      % Copy the master instdispance data to the working instance
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
        p_dest(i, :) = typecast(reshape(encrypted(i,:), 1, []), 'uint8');
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
      ks = zeros(4, 4, 'uint32');
      ks(1,:) = bitand(p_instance.x(1), 255, 'uint32');

      for i = 2:4   
        ks(i,:) = bitand(bitshift(p_instance.x(i), -(8*(i-1)), 'uint32'), 255, 'uint32');
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
  end
end

%%
