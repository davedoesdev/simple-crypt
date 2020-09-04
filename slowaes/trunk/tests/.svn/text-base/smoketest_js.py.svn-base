""" Some very-elementary "smoke tests".
"""
import smutil

def main():
    print 'Begin all modes check'
    plaintext = 'Hello, World! Have a great day...'
    for smode in smutil.modes:
        mode = smutil.slowaesdo('modeOfOperation.%s', smode)
        skey = 'Call me Ishmael.'[:16]
        akey = smutil.cryptohelpersdo('convertStringToByteArray(%r)', skey);
        keysize = smutil.slowaesdo('aes.keySize.SIZE_128')
        nkey = smutil.slowaesdo('getPaddedBlock(%r, 0, 16, %s)', akey, mode)
        assert nkey == smutil.str2nums(skey), 'FAILED: mode %r (%s) key conversion' % (smode, mode)
        print 'PASSED: mode %r (%s) key conversion' % (smode, mode)
        iv = [12, 34, 96, 15] * 4
	utf8string = smutil.cryptohelpersdo('encode_utf8(%r)', plaintext)
	byteArray = smutil.cryptohelpersdo('convertStringToByteArray(%r)', utf8string)
	enc = smutil.slowaesdo('encrypt(%r, %s, %r, %s, %r)',
            byteArray, mode, nkey, keysize, iv)
        dec = smutil.slowaesdo('decrypt(%r, %s, %r, %r, %s, %r)',
            enc['cipher'], enc['originalsize'], enc['mode'], nkey,
            keysize, iv)
	decstring = smutil.cryptohelpersdo('convertByteArrayToString(%r)', dec)
	unicodestring = smutil.cryptohelpersdo('decode_utf8(%r)', decstring)
	assert unicodestring == plaintext, 'FAILED: mode %r (%s) round trip encryption/decryption' % (smode, mode)
        print 'PASSED: mode %r (%s) round trip encryption/decryption' % (smode, mode)
    
    print '\nBegin FIPS 128 verification'
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    f128keysize = smutil.slowaesdo('aes.keySize.SIZE_128')
    f128block = smutil.cryptohelpersdo('toNumbers("00112233445566778899aabbccddeeff")')
    f128ciph = smutil.cryptohelpersdo('toNumbers("69c4e0d86a7b0430d8cdb78070b4c55a")')
    f128key = smutil.cryptohelpersdo('toNumbers("000102030405060708090a0b0c0d0e0f")')
    f128enc = smutil.slowaesdo('aes.encrypt(%r, %r, %s)', f128block, f128key, f128keysize)
    assert f128enc == f128ciph, 'FAILED: FIPS 128 encryption'
    print 'PASSED: FIPS 128 encryption'
    f128dec = smutil.slowaesdo('aes.decrypt(%r, %r, %s)', f128ciph, f128key, f128keysize)
    assert f128dec == f128block, 'FAILED: FIPS 128 decryption'
    print 'PASSED: FIPS 128 decryption'

    print '\nBegin FIPS 192 verification'
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    f192keysize = smutil.slowaesdo('aes.keySize.SIZE_192')
    f192block = smutil.cryptohelpersdo('toNumbers("00112233445566778899aabbccddeeff")')
    f192ciph = smutil.cryptohelpersdo('toNumbers("dda97ca4864cdfe06eaf70a0ec0d7191")')
    f192key = smutil.cryptohelpersdo('toNumbers("000102030405060708090a0b0c0d0e0f1011121314151617")')
    f192enc = smutil.slowaesdo('aes.encrypt(%r, %r, %s)', f192block, f192key, f192keysize)
    assert f192enc == f192ciph, 'FAILED: FIPS 192 encryption'
    print 'PASSED: FIPS 192 encryption'
    f192dec = smutil.slowaesdo('aes.decrypt(%r, %r, %s)', f192ciph, f192key, f192keysize)
    assert f192dec == f192block, 'FAILED: FIPS 192 decryption'
    print 'PASSED: FIPS 192 decryption'

    print '\nBegin FIPS 256 verification'
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    f256keysize = smutil.slowaesdo('aes.keySize.SIZE_256')
    f256block = smutil.cryptohelpersdo('toNumbers("00112233445566778899aabbccddeeff")')
    f256ciph = smutil.cryptohelpersdo('toNumbers("8ea2b7ca516745bfeafc49904b496089")')
    f256key = smutil.cryptohelpersdo('toNumbers("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")')
    f256enc = smutil.slowaesdo('aes.encrypt(%r, %r, %s)', f256block, f256key, f256keysize)
    assert f256enc == f256ciph, 'FAILED: FIPS 256 encryption'
    print 'PASSED: FIPS 256 encryption'
    f256dec = smutil.slowaesdo('aes.decrypt(%r, %r, %s)', f256ciph, f256key, f256keysize)
    assert f256dec == f256block, 'FAILED: FIPS 256 decryption'
    print 'PASSED: FIPS 256 decryption'

    print '\nBegin OpenSSL 128 verification'
    keysize = smutil.slowaesdo('aes.keySize.SIZE_128')
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    key = smutil.cryptohelpersdo('toNumbers("5e884898da28047151d0e56f8dc62927")')
    iv = smutil.cryptohelpersdo('toNumbers("6bbda7892ad344e06c31e64564a69a9a")')
    plaintext = smutil.cryptohelpersdo('convertStringToByteArray("secretsecretsecret")')
    openssl = '4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=\n'
    enc = smutil.slowaesdo('encrypt(%r, %s, %r, %s, %r).cipher', plaintext, mode, key, keysize, iv)
    base64 = smutil.cryptohelpersdo('base64.encode(%r)', enc);
    assert base64 == openssl, 'FAILED: OpenSSL 128 encryption'
    print 'PASSED: OpenSSL 128 encryption'

    print '\nBegin OpenSSL 192 verification'
    keysize = smutil.slowaesdo('aes.keySize.SIZE_192')
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    key = smutil.cryptohelpersdo('toNumbers("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6")')
    iv = smutil.cryptohelpersdo('toNumbers("6bbda7892ad344e06c31e64564a69a9a")')
    plaintext = smutil.cryptohelpersdo('convertStringToByteArray("secretsecretsecret")')
    openssl = 'g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=\n'
    enc = smutil.slowaesdo('encrypt(%r, %s, %r, %s, %r).cipher', plaintext, mode, key, keysize, iv)
    base64 = smutil.cryptohelpersdo('base64.encode(%r)', enc);
    assert base64 == openssl, 'FAILED: OpenSSL 192 encryption'
    print 'PASSED: OpenSSL 192 encryption'

    print '\nBegin OpenSSL 256 verification'
    keysize = smutil.slowaesdo('aes.keySize.SIZE_256')
    mode = smutil.slowaesdo('modeOfOperation.CBC')
    key = smutil.cryptohelpersdo('toNumbers("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")')
    iv = smutil.cryptohelpersdo('toNumbers("6bbda7892ad344e06c31e64564a69a9a")')
    plaintext = smutil.cryptohelpersdo('convertStringToByteArray("secretsecretsecret")')
    openssl = 'XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=\n'
    enc = smutil.slowaesdo('encrypt(%r, %s, %r, %s, %r).cipher', plaintext, mode, key, keysize, iv)
    base64 = smutil.cryptohelpersdo('base64.encode(%r)', enc);
    assert base64 == openssl, 'FAILED: OpenSSL 256 encryption'
    print 'PASSED: OpenSSL 256 encryption'
main()

