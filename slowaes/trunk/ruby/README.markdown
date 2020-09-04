## gibberish-aes-ruby

---

Written by Alex Boussinet <mailto:alex.boussinet@gmail.com>  
Modified by Mark Percival <mailto:mark@mpercival.com>

This ruby gem is simply a modification of Alex Boussinet's Ruby-AES(normal implemenation)
which can be found at <http://raa.ruby-lang.org/project/ruby-aes/>

I've fixed 2 issues to make it compatible with OpenSSL:

- Correctly padding the blocks
- Generating a key and IV from a password and random salt

# 
    require 'rubygems'
    require 'ruby-aes'
    require 'base64'

    enc = Aes.openssl_encrypt("pass", "test", :salt => "1831BD4EC8E35CC8", :size => 256, :mode => 'CBC')
    p Base64.b64encode(enc[:salted])
    dec = Aes.openssl_decrypt("pass", enc[:salted])
    p dec


Valid modes are:

- ECB (Electronic Code Book)
- CBC (Cipher Block Chaining)
- OFB (Output Feedback)
- CFB (Cipher Feedback)

Valid key length:

- 128 bits
- 192 bits
- 256 bits

For a really good encryption, 256 bits CBC is recommanded.

For more information on AES-Rijndael, see: <http://csrc.nist.gov/encryption/aes/rijndael/>
