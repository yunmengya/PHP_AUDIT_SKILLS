import pickle as p


__import__('pickle')

b = 'pickle'
__import__(b)

c = __import__
c(b)

importlib.import_module(b)

d = importlib
d.import_module(b)

x = p.loads

loads_func = getattr(p, 'loads')

a = getattr
a(p, ...)

