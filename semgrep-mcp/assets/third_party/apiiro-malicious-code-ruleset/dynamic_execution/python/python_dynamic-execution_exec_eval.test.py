# TP

exec("print('Literal exec')")

exec('print("Literal exec with single quotes")')

param = 1
def dynamic_exec(code):
    exec(code)
dynamic_exec(param)

from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher_suite = Fernet(key)
cipher_text = cipher_suite.encrypt(b"print('Hello')")
exec(cipher_suite.decrypt(cipher_text))

eval(param)

eval('print("Literal eval with single quotes")')


# FP

def other_exec(code):
    print(code)
other_exec(param)

import someModule  # Simulate an imported module
someModule.exec('print("Imported module exec")')

class SomeClass:
    def exec(self, param):
        print(param)
instance = SomeClass()
instance.exec('print("Called attribute exec")')

def dynamic_eval(code):
    run(code)
dynamic_eval(param)

_eval(cipher_suite.decrypt(cipher_text).decode())

def other_eval(code):
    print(code)
other_eval('print("Custom method same name for eval")')

import someModule
someModule.eval('print("Imported module eval")')

class SomeClass:
    def eval(self, param):
        console.log(param)
instance = SomeClass()
instance.eval('print("Called attribute eval")')
