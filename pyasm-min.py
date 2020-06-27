
import os, sys, types

def writet(t):
    return sys.stdo.write(t.encode())

sys.stdo = os.fdopen(sys.stdout.fileno(), 'wb', 0)
try:
    sys.stdout = types.SimpleNamespace(write=writet, flush=lambda:None)
except AttributeError:
    sys.stdout = sys.stdo

def exe(tup):
    types.FunctionType(types.CodeType(*tup), globals())()
