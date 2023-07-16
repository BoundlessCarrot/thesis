%%
function result = rabbit_rotl(x, rot)
    result = bitshift(x, rot) + bitshift(x, rot - 32);
end
%%
