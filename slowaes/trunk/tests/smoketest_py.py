""" Some very-elementary "smoke tests".
"""
import os
import sys
import pyutil

def runHighLevelFunctionTests():

    generateRandomKey = pyutil.aes.generateRandomKey
    encryptData = pyutil.aes.encryptData
    decryptData = pyutil.aes.decryptData
    AES = pyutil.aes.AES
    
    def testString(cleartext):
        ##print 'testing for data of length %s' % len(cleartext)
        for (keyname, keylen) in AES.keySize.items():
            ##print 'trying with key size %s' % keyname,
            key = generateRandomKey(keylen)
            ciph = encryptData(key, cleartext)
            decr = decryptData(key, ciph)
            assert decr == cleartext
            ##print 'ok'

    # full block - adds full block of padding
    print 'testing full block padding.'
    testString(''.join('a' for i in range(16)))

    # partial block
    print 'testing partial block padding.'
    cleartext = ("This is a test! Let's try something without a perfect "
                  "block size...")
    assert len(cleartext) % 16
    testString(cleartext)

    character_range = map(chr, range(256))

    def getRandomChars(count):
        import random
        random_chars = []
        for i in range(count):
            random_chars.append(random.choice(character_range))
        return random_chars

    sizes = [8, 16, 22, 32, 33, 1600, 4092]

    # test sizes
    print 'testing various messages sizes'
    for size in sizes:
        print 'testing message of size %s (with 3 key sizes)' % size
        cleartext = 'a' * size
        testString(cleartext)

    # test charset
    print 'testing each of 256 characters with both full and partial padding'
    failed_chars = []
    for i in range(256):
        # test both full and partial padding
        for count in (12, 16):
            cleartext = chr(i) * count
            try:
                testString(cleartext)
            except:
                print 'failed with %s' % cleartext, i
                failed_chars.append(i)
            if failed_chars:
                raise StandardError, 'these failed %s' % str(failed_chars)

    # test random chars
    print 'testing random chracters of various sizes'
    for size in sizes:
        print 'testing message of size %s (with 3 key sizes)' % size
        cleartext = ''.join(getRandomChars(size))
        try:
            testString(cleartext)
        except Exception:
            print 'failed with %s' % cleartext
            raise

def main():
    plaintext = 'Hello, World! Have a great day...'
    moo = pyutil.aes.AESModeOfOperation()
    for smode in pyutil.modes:
        pymode = moo.modeOfOperation[smode]
        print 'mode %r (%s)' % (smode, pymode)
        skey = 'Call me Ishmael.'[:16]
        nkey = pyutil.str2nums(skey)
        assert skey == pyutil.nums2str(nkey)
        iv = [12, 34, 96, 15] * 4

        pymo, pyos, pyen = moo.encrypt(plaintext, pymode, nkey, len(nkey), iv)
        print '  PY enc (mode=%s, orgsize=%s):' % (pymo, pyos)
        print ' ', pyen

        pydec = moo.decrypt(pyen, pyos, pymo, nkey, len(nkey), iv)
        print '  PY dec (mode=%s, orgsize=%s):' % (pymo, pyos)
        print ' ', repr(pydec)


if __name__ == '__main__':
    main()
    runHighLevelFunctionTests()
