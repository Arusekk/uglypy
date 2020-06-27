
import argparse
import dis
import sys
import types
import os

from pwnlib.util import safeeval

if sys.version_info[:2] < (3,6):
    ARGMASKLEN = 16
    def simple_op(op):
        return bytes((op,))
else:
    ARGMASKLEN = 8
    def simple_op(op):
        return bytes((op, 0))

if sys.version_info[0] < 3:
    def bytes(p):
        return b''.join(map(chr, p))

ARGMASK = (1<<ARGMASKLEN)-1

def basic_op(op, arg):
    l = arg.bit_length()
    if l <= ARGMASKLEN:
        return bytes((op, arg&0xff, arg>>8))[:(ARGMASKLEN>>3)+1]
    return basic_op(dis.opmap['EXTENDED_ARG'], arg>>ARGMASKLEN) + basic_op(op, arg&ARGMASK)

def find(co, consts):
    try:
        idx = consts.index(co)
    except ValueError:
        idx = len(consts)
        consts.append(co)
    return idx

def line2code(line, consts, names, varnames, labels, code):
    kwdargs = line.split()
    kwd, args = kwdargs[0], kwdargs[1:]
    if not args and kwd.endswith(':'):
        lbl = kwd[:-1]
        pos = len(code)
        labels[lbl] = pos
        for off in labels.pop(kwd, ()):
            eoff = off+(ARGMASKLEN>>3)
            posx = pos
            if code[off-1] in dis.hasjrel:
                posx -= eoff
            code[off:eoff] = basic_op(0, posx)[1:]
        return b''
    op = dis.opmap[kwd]
    if op < dis.HAVE_ARGUMENT:
        assert not args
        return simple_op(op)
    if op in dis.hasconst:
        co = safeeval.const(' '.join(args))
        arg = find(co, consts)
    elif op in dis.hasname:
        arg, = args
        arg = find(arg, names)
    elif op in dis.haslocal:
        arg, = args
        arg = find(arg, varnames)
    elif op in dis.hasjabs + dis.hasjrel:
        arg, = args
        if arg in labels:
            arg = labels[arg]
            if op in dis.hasjrel:
                arg -= len(code)+1+(ARGMASKLEN>>3)
        else:
            labels.setdefault(arg+':', []).append(len(code)+1)
            arg = ARGMASK
    elif op in dis.hascompare:
        arg, = args
        arg = dis.cmp_op.index(arg)
    else:
        arg, = args
        arg = int(arg, 0)
    return basic_op(op, arg)

def writet(t):
    return sys.stdo.write(t.encode())

def includecode(filename):
    code = types.CodeType
    with open(filename, 'r') as fp:
      return code(*filecode(fp))

def filecode(fp, arg=None):
    constants, names, varnames, labels = [], [], [], {}
    codestring = bytearray()
    comment = False
    lnotab = bytearray(b'\0\0')
    firstlineno = 0
    filename = fp.name
    for lineno, line in enumerate(fp):
        lnotab[-1] += 1
        line = line.strip()
        if not line: continue

        if line == '/*':
            comment = True
        if not comment:
            if '$arg1$' in line:
                line = line.replace('$arg1$', str(arg.plus.pop(0)))
            if firstlineno == 0:
                firstlineno = lineno + 1
                lnotab[-1] = 1
            codenew = line2code(line, constants, names, varnames, labels, codestring)
            if not codenew:
                continue
            lnotab[-2] += len(codenew)
            codestring += codenew
            lnotab += b'\0\0'
        if line == '*/':
            comment = False

    argcount = 0
    kwonlyargcount = 0
    nlocals = len(varnames)
    stacksize = 16 # XXX
    flags = 0
    codestring = bytes(codestring)
    constants = tuple(constants)
    names = tuple(names)
    varnames = tuple(varnames)
    name = "<module>"
    lnotab = bytes(lnotab[:-2])
    codeargs = (argcount, kwonlyargcount, nlocals, stacksize, flags, codestring,
                constants, names, varnames, filename, name, firstlineno, lnotab)
    if sys.version_info[0] < 3:
        codeargs = codeargs[:1] + codeargs[2:]
    return codeargs

def main():
    par = argparse.ArgumentParser()
    par.add_argument("infile", type=argparse.FileType('r'))
    par.add_argument("--flush-stdout", action='store_true')
    par.add_argument("--print-only", action='store_true')
    par.add_argument("plus", type=safeeval.const, nargs='*')
    arg = par.parse_args()

    if arg.flush_stdout:
        sys.stdo = os.fdopen(sys.stdout.fileno(), 'wb', 0)
        try:
            sys.stdout = types.SimpleNamespace(write=writet, flush=lambda:None)
        except AttributeError:
            sys.stdout = sys.stdo

    with arg.infile as fp:
        codeargs = filecode(fp, arg=arg)
    print(codeargs)
    if arg.print_only: return
    code = types.CodeType
    co = code(*codeargs)
    dis.dis(co)

    print("executing :)")
    print(repr(main.__class__(co, main.__globals__)(*arg.plus)))

if __name__ == "__main__":
    main()
