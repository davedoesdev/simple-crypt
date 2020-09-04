""" Some very-elementary "smoke tests".
"""
import pyutil
import smutil

def main():
    plaintext = 'Hello, World! Have a great day...'
    moo = pyutil.aes.AESModeOfOperation()
    for smode in smutil.modes:
        mode = smutil.slowaesdo('modeOfOperation.%s', smode)
        print 'JS mode %r (%s)' % (smode, mode)
        skey = 'Call me Ishmael.'[:16]
        nkey = smutil.cryptohelpersdo('convertStringToByteArray(%r, 0, 16, %s)',
                                      skey, mode)
        assert nkey == smutil.str2nums(skey)
        iv = [12, 34, 96, 15] * 4
        enc = smutil.slowaesdo('encrypt(%r, %s, %r, %s, %r)',
            plaintext, mode, nkey, len(nkey), iv)
        encos = enc['originalsize']
        encmo = enc['mode']
        encen = enc['cipher']
        print '  JS enc (mode=%s, orgsize=%s):' % (encmo, encos)
        print ' ', encen # smutil.str2nums(encen)

        pymode = moo.modeOfOperation[smode]
        print 'PY mode %r (%s)' % (smode, pymode)
        pymo, pyos, pyen = moo.encrypt(plaintext, pymode, nkey, len(nkey), iv)
        print '  PY enc (mode=%s, orgsize=%s):' % (pymo, pyos)
        print ' ', pyen

        dec = smutil.slowaesdo('decrypt(%r, %s, %r, %r, %s, %r)',
            encen, encos, encmo, nkey, len(nkey), iv)
        print '  JS dec (mode=%s, orgsize=%s):' % (encmo, encos)
        print ' ', repr(dec)

        pydec = moo.decrypt(pyen, pyos, pymo, nkey, len(nkey), iv)
        print '  PY dec (mode=%s, orgsize=%s):' % (pymo, pyos)
        print ' ', repr(pydec)



main()
