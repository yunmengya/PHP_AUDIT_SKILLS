import pickle


# TP

def my_func():
    print("Hello from deserialized function")
func1 = pickle.loads(b'\x80\x03c__main__\nmy_func\nq\x00.')
func1()

pickle.loads(b'\x80\x03c__main__\nmy_func\nq\x00.')()

pickle.loads(param)()

def dynamic_pickle(code):
    pickled_code = pickle.dumps(code)
    loaded_func = pickle.loads(pickled_code)
    loaded_func()
dynamic_pickle(lambda: print("Pickle with parameter"))

pickled_code = pickle.dumps(lambda: cipher_suite.decrypt(cipher_text).decode())
loaded_func = pickle.loads(pickled_code)
loaded_func()


# FP

def my_func():
    print("Static function")
a = pickle.loads(b'\x80\x03c__main__\nmy_func\nq\x00.')

pickle.loads(b'\x80\x03c__main__\nmy_func\nq\x00.')

x = pickle.loads(b'\x80\x03c__main__\nmy_func\nq\x00.')
print(x)

def other_pickle(code):
    pickle_loads = print(code)
other_pickle("exec(print(1))")

import someModule
someModule.pickle.dumps(lambda: print("Pickle in imported module"))
someModule.pickle.loads(pickled_code)

class SomeClass:
    class pickle:
        def loads(self, code):
            print(1)
instance = SomeClass()
instance.pickle.loads(lambda: print("Pickle with class method"))

pickled_code = pickle.dumps(lambda: print("Pickle loaded and executed"))
data_only = pickle.loads(pickled_code)
