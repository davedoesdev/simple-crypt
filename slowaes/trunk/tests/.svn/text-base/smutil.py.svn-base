""" Common utility routines for spidermonkey use on the JS AES module
"""
import os
import spidermonkey

modes = 'OFB CFB CBC'.split()

def do(s):
    return cx.eval_script(s)

class ConsoleClass:
  """Let JS code call console.log(...) for output."""
  def log(self, s): print s
console = ConsoleClass()

def init():
    rt = spidermonkey.Runtime()
    cx = rt.new_context()
    cx.bind_class(ConsoleClass)
    cx.bind_object('console', console)
    directory, fn = os.path.split(__file__)
    jsdir = os.path.join(directory, '../js/')
    chFile = os.path.join(jsdir, 'cryptoHelpers.js')
    f = open(chFile)
    chScript = f.read()
    f.close()
    aesFile = os.path.join(jsdir, 'aes.js')
    f = open(aesFile)
    aesScript = f.read()
    f.close()
    cx.eval_script(chScript)
    cx.eval_script(aesScript)
    return cx
cx = init()

def slowaesdo(method, *args):
    return do('slowAES.%s' % (method%args))

def cryptohelpersdo(method, *args):
    return do('cryptoHelpers.%s' % (method%args))

def str2nums(s):
    return map(ord, s)

def nums2str(ns):
    return ''.join(map(chr, ns))
