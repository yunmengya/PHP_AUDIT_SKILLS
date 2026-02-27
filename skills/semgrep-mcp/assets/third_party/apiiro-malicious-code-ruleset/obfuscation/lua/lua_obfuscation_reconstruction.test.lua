-- TP
local result = table.concat({'a', 'b', 'c', 'd', 'e', 1}, '')

local a = ''
for i, v in ipairs({'a', 'b', 'c', 'd', 'e', 1}) do
    a = a .. tostring(v)
end

local b = ''
for i = 1, #{'a', 'b', 'c', 'd', 'e', 1} do
    b = b .. tostring({'a', 'b', 'c', 'd', 'e', 1}[i])
end


-- FP
local result = table.concat({'a', 'b', 'c', 'd', 'e', 1, a}, '')

local x = "Hello" .. " " .. "World" .. "y"
