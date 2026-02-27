math.abs = function(x)
    print("New math.abs called")
    return x >= 0 and x or -x
end

getmetatable("").__concat = function(a, b)
    return a .. b .. " (custom)"
end

debug.setmetatable(0, {
    __add = function(a, b)
        return (a * 10) + b
    end
})
