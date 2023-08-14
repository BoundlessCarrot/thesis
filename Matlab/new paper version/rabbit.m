%%

classdef Rabbit
  properties
    carry
    counter
    % g
    key
    s
    state
  end
  methods
    function obj = Rabbit(key)
      obj.carry = 0;
      obj.counter = uint32([0:8]);
      % obj.g = uint32([0;0;0;0;0;0;0;0]);
      obj.key = [typecast(uint8(key[0:2]), 'uint16')) ...
        typecast(uint8(key[2:4]), 'uint16') ...
        typecast(uint8(key[4:6]), 'uint16') ...
        typecast(uint8(key[6:8]), 'uint16') ...
        typecast(uint8(key[8:10]), 'uint16') ...
        typecast(uint8(key[10:12]), 'uint16') ...
        typecast(uint8(key[12:14]), 'uint16') ...
        typecast(uint8(key[14:16]), 'uint16') ...
      ];
      obj.s = uint128(0);
      obj.state = uint32([0:8]);
    end

    function key_setup(obj)
      obj.key_expansion();
      
      for j = 1:4
        obj.update();
      end

      for k = 1:8
        obj.counter(k) = bitxor(obj.counter(k), obj.state(rem(k + 4, 8)));
      end
    end

    function key_expansion(obj)
      for i = 1:8
        if rem(i, 2) == 0
          obj.state(i) = bitconcat(bitsliceget(obj.key(rem(i+1, 8))), bitsliceget(obj.key(i))));
          obj.counter(i) = bitconcat(bitsliceget(obj.key(rem(i+4, 8))), bitsliceget(obj.key(rem(i+5, 8))));
        else
          obj.state(i) = bitconcat(bitsliceget(obj.key(rem(i+5, 8))), bitsliceget(obj.key(rem(i+4, 8))));
          obj.counter(i) = bitconcat(bitsliceget(obj.key(i))), bitsliceget(obj.key(rem(i+1, 8))));
        end
      end
    end


    function update(obj)
      for i = 1:8
        g(i) = mod(bitxor((obj.state(i) + obj.counter(i))^2, bitshift((obj.state(i) + obj.counter(i))^2, 32)), 2^32);
      end

      obj.state(1) = g(1) + bitrotate(g(8), 16) + bitrotate(g(7), 16);
      obj.state(2) = g(2) + bitrotate(g(1), 16) + bitrotate(g(8), 16);
      obj.state(3) = g(3) + bitrotate(g(2), 16) + bitrotate(g(1), 16);
      obj.state(4) = g(4) + bitrotate(g(3), 16) + bitrotate(g(2), 16);
      obj.state(5) = g(5) + bitrotate(g(4), 16) + bitrotate(g(3), 16);
      obj.state(6) = g(6) + bitrotate(g(5), 16) + bitrotate(g(4), 16);
      obj.state(7) = g(7) + bitrotate(g(6), 16) + bitrotate(g(5), 16);
      obj.state(8) = g(8) + bitrotate(g(7), 16) + bitrotate(g(6), 16);

      obj.counter_update();
    end

    function counter_update(obj)
      new_carry = 0;
      a = [ 0x4D34D34D 0xD34D34D3 0x34D34D34 0x4D34D34D 0xD34D34D3 0x34D34D34 0x4D34D34D 0xD34D34D3 ];
      for i = 1:8
        if obj.counter(1) + a(1) + bitget(obj.carry(8)) >= 2^32 && i == 1
          bitset(new_carry, i, 1);
        else if obj.counter(i) + a(i) + bitget(obj.carry(i-1)) >= 2^32 && i > 0
          bitset(new_carry, i, 1);
        else
          bitset(new_carry, i, 0);
        end 
      end
      
      obj.carry = new_carry;

      obj.counter(1) = mod(obj.counter(1) + a(1) + bitget(obj.carry, 8), 2^32);
      obj.counter(2) = mod(obj.counter(2) + a(2) + bitget(obj.carry, 1), 2^32);
      obj.counter(3) = mod(obj.counter(3) + a(3) + bitget(obj.carry, 2), 2^32);
      obj.counter(4) = mod(obj.counter(4) + a(4) + bitget(obj.carry, 3), 2^32);
      obj.counter(5) = mod(obj.counter(5) + a(5) + bitget(obj.carry, 4), 2^32);
      obj.counter(6) = mod(obj.counter(6) + a(6) + bitget(obj.carry, 5), 2^32);
      obj.counter(7) = mod(obj.counter(7) + a(7) + bitget(obj.carry, 6), 2^32);
      obj.counter(8) = mod(obj.counter(8) + a(8) + bitget(obj.carry, 7), 2^32);
    end

    function extract(obj)
      % xor_op1 = bitxor(bitsliceget(obj.state(0), 1, 16), bitsliceget(obj.state(5), 17, 32));

      % for i = 1:16
      %   bitset(obj.s, i, xor_op(i));
      % end

      % xor_op2 = bitxor(bitsliceget(obj.state(0), 17, 32), bitsliceget(obj.state(3), 1, 16));

      % for i = 17:32
      %   bitset(obj.s, i, xor_op(i));
      % end

      % xor_op3 = bitxor(bitsliceget(obj.state(2), 1, 16), bitsliceget(obj.state(7), 17, 32));

      % for i = 33:48
      %   bitset(obj.s, i, xor_op(i));
      % end

      % xor_op4 = bitxor(bitsliceget(obj.state(2), 17, 32), bitsliceget(obj.state(5), 1, 16));

      % for i = 49:64
      %   bitset(obj.s, i, xor_op(i));
      % end

      % xor_op5 = bitxor(bitsliceget(obj.state(4), 1, 16), bitsliceget(obj.state(1), 17, 32));

      % for i = 33:48
      %   bitset(obj.s, i, xor_op(i));
      % end

      new_s = [0:128];

      new_s(1:16) = bitxor(bitsliceget(obj.state(0), 1, 16), bitsliceget(obj.state(5), 17, 32));
      new_s(17:32) = bitxor(bitsliceget(obj.state(0), 17, 32), bitsliceget(obj.state(3), 1, 16));
      new_s(33:48) = bitxor(bitsliceget(obj.state(2), 1, 16), bitsliceget(obj.state(7), 17, 32));
      new_s(49:64) = bitxor(bitsliceget(obj.state(2), 17, 32), bitsliceget(obj.state(5), 1, 16));
      new_s(65:80) = bitxor(bitsliceget(obj.state(4), 1, 16), bitsliceget(obj.state(1), 17, 32));
      new_s(81:96) = bitxor(bitsliceget(obj.state(4), 17, 32), bitsliceget(obj.state(7), 1, 16));
      new_s(97:112) = bitxor(bitsliceget(obj.state(6), 1, 16), bitsliceget(obj.state(3), 17, 32));
      new_s(113:128) = bitxor(bitsliceget(obj.state(6), 17, 32), bitsliceget(obj.state(1), 1, 16));
      
      obj.s = typecast(uint8(new_s), 'uint128');
    end

    function output = crypt(obj, msg)
      obj.extract();
      % will likely need some massaging, the datatype probably won't match here
      output = bitxor(msg, obj.s);
    end

    function iv_setup(obj, iv)
      obj.counter(1) = bitxor(obj.counter(1), bitsliceget(iv, 1, 32));
      obj.counter(2) = bitxor(obj.counter(2), bitconcat(bitsliceget(iv, 49, 64), bitsliceget(iv, 17, 32)));
      obj.counter(3) = bitxor(obj.counter(3), bitsliceget(iv, 33, 64));
      obj.counter(4) = bitxor(obj.counter(4), bitconcat(bitsliceget(iv, 33, 48), bitsliceget(iv, 1, 16)));
      obj.counter(5) = bitxor(obj.counter(5), bitsliceget(iv, 1, 32));
      obj.counter(6) = bitxor(obj.counter(6), bitconcat(bitsliceget(iv, 49, 64), bitsliceget(iv, 17, 32)));
      obj.counter(7) = bitxor(obj.counter(7), bitsliceget(iv, 33, 64));
      obj.counter(8) = bitxor(obj.counter(8), bitconcat(bitsliceget(iv, 33, 48), bitsliceget(iv, 1, 16)));

      for i = 1:4
        obj.update();
      end
    end
  end
end

%%
