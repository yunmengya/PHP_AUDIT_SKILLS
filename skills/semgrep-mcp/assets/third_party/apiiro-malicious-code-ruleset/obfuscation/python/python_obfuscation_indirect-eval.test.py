# Alternative executions

import builtins
import pickle as p


builtins.eval('...')

func=eval

getattr(__builtins__, 'eval')

globals()['__builtins__'].eval("...")

a = builtins
f = 1
a.eval('...')

gettatr(__builtins__, 'eval')

a = builtins;f = 1;a.eval('...')

b = getattr
e = b(__builtins__, 'eval')

b = __builtins__
getattr(b, 'eval')

b = __builtins__
c = getattr
d = 'eval'
e = b(c, d)

b = getattr
c = __builtins__
e = b(c, 'eval')('...')

x = globals()['__builtins__']
x.eval("...")

x = __builtins__
y = globals()[x]
y.eval("...")
