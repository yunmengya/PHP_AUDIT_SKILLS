local code1 = "..."
local func1 = load(code1)
print(func1())

local code2 = "..."
local func2 = loadstring(code2)
print(func2())

os.execute("lua -e '...'")