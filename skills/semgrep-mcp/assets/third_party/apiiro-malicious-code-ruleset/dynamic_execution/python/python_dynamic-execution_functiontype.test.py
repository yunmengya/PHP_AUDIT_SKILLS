
from types import FunctionType
from cryptography.fernet import Fernet


# TP

a = FunctionType(compile('print(1)', 'method', 'exec'), {})
a()

FunctionType(compile(param, "", "eval"), globals())()

def method(code):
    compiled_code = compile(code, 'run', 'exec')
    b = FunctionType(compiled_code, {})
    b()

def dynamic_compile(code):
    compiled_code = compile(code, '', 'eval')
    return FunctionType(compiled_code, {})
dynamic_compile(param)

compiled_code = compile(cipher_suite.decrypt(cipher_text).decode(), 'compiled', 'exec')
c = FunctionType(compiled_code, globals())
thing = 1
c()


# FP

def custom_FunctionType(code, _dict):
    print(code)
compiled_code = compile("print(1)", 'str', 'eval')
custom_FunctionType(compiled_code, {'a': 1})

import someModule
compiled_code = compile('print(1)', 'send', 'exec')
someModule.FunctionType(compiled_code, {})()

class Other:
    def FunctionType(self, code):
        print(code)
compiled_code = compile("print(1)", 'socket', 'eval')
d = Other().FunctionType(compiled_code, {})
d()
