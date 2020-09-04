""" Common utility routines for Python use on the Python AES module
"""
import os
import sys

modes = 'OFB CFB CBC'.split()

def init():
    directory, fn = os.path.split(__file__)
    pydir = os.path.join(directory, '../python/')
    sys.path.insert(1, pydir)
    import aes
    return aes
aes = init()

def str2nums(s):
    return map(ord, s)

def nums2str(ns):
    return ''.join(map(chr, ns))
