import builtins
import pickle as p


builtins.exec('...')

func=exec

getattr(__builtins__, 'exec')

globals()['__builtins__'].exec("...")

a = builtins
f = 1
a.exec('...')

gettatr(__builtins__, 'exec')

a = builtins;f = 1;a.exec('...')

b = getattr
e = b(__builtins__, 'exec')

b = __builtins__
getattr(b, 'exec')

b = __builtins__
c = getattr
d = 'exec'
e = b(c, d)

b = getattr
c = __builtins__
e = b(c, 'exec')('...')

x = globals()['__builtins__']
x.exec("...")

x = __builtins__
y = globals()[x]
y.exec("...")

