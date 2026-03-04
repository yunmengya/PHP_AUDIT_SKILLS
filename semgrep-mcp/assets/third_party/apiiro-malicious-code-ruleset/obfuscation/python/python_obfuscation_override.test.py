# TP
__import__('os')
globals()['foo'] = 42
globals().update({'foo': 42})

def Exception(): pass
Exception = 42
setattr(__builtins__, 'str', 42)


# FP
x = (True or False)
def my_function(): pass
my_var = Exception
setattr(obj, 'foo', 42)
while(x):
    pass