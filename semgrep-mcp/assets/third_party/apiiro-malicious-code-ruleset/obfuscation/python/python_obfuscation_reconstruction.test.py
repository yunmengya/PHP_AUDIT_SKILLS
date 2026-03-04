# TP

lst = [72, 101, 108, 108, 111, 5]
x = ''.join([i for i in lst])

x = ''.join([i for i in [72, 101, 'o', 'oo', 108, 111]])

lst = [72, 0x101, 108, 108, 111, 5]
a = ''.join([chr(ch) for ch in lst])

s = ''.join([chr(i) for i in [72, 101, 108, 108, 111, 0o42]])

lst = ['h', 'e', 'l', 'l', 'o']
x = ''.join([ch for ch in lst])


# FP

VAR2 = [1, a, 2, 3]
y2 = ''.join([str(C) for C in VAR2]) 
