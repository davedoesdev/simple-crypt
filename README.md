# simple-crypt&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/simple-crypt.png)](https://travis-ci.org/davedoesdev/simple-crypt) [![Coverage Status](https://coveralls.io/repos/davedoesdev/simple-crypt/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/simple-crypt?branch=master) [![NPM version](https://badge.fury.io/js/simple-crypt.png)](http://badge.fury.io/js/simple-crypt)

Javascript library for signing and encrypting data.

- Consistent API across Node.js and browser.
- On Node.js wraps [crypto](http://nodejs.org/api/crypto.html) and [ursa](https://github.com/Obvious/ursa) modules.
- On browser wraps [SlowAES](https://code.google.com/p/slowaes/), [pbkdf2.js](http://anandam.name/pbkdf2/), [CryptoJS](https://code.google.com/p/crypto-js/), [jsrsasign](http://kjur.github.io/jsrsasign/) and [js-rsa-pem](https://bitbucket.org/adrianpasternak/js-rsa-pem/wiki/Home).
- Hard-coded to HMAC-SHA-256 for symmetric signing.
- Hard-coded to RSA-SHA-256 with [RSASSA-PSS](http://tools.ietf.org/html/rfc3447#section-8.1) encoding for asymmetric signing.
- Hard-coded to AES-128-CBC for symmetric key encryption (with optional SHA-256 checksum).
- Hard-coded to RSA, [RSAES-OAEP](http://tools.ietf.org/html/rfc3447#section-7.1) encoding and AES-128-CBC for asymmetric encryption (with optional SHA-256 checksum).
- Verification and decryption operations included.
- Support for deriving signing and encryption key from a password using PBKDF2-SHA1.
- JSON encoding of data by default.
- Unit tests, including NIST test vectors and tests for interoperability between Node.js and browser (using [PhantomJS](http://phantomjs.org/)).

Example:

```javascript
var Crypt = require('simple-crypt').Crypt;
var data = { device_id: 'temperature_sensor0', value: 15.765 };

Crypt.make('my signing key', function (err, signer)
{
    signer.sign(data, function (err, signed)
    {
        Crypt.make(this.get_key(), function (err, verifier)
        {
            verifier.verify(signed, function (err, verified)
            {
                assert.deepEqual(verified, data);
            });
        });
    });
});
```

The API is described [here](#tableofcontents).

Please feel free to make any comments (or pull requests), especially if you notice something wrong!

## Installation

Node.js:

``` shell
npm install simple-crypt
```

Browser:

```html
<script type="text/javascript" src="dist/simple-crypt-deps.js"></script>
<script type="text/javascript" src="dist/simple-crypt.js"></script>
```

## More Examples

### Encryption

```javascript
Crypt.make(crypto.randomBytes(Crypt.get_key_size()), function (err, encrypter)
{
    encrypter.encrypt(data, function (err, encrypted)
    {
        Crypt.make(this.get_key(), function (err, decrypter)
        {
            decrypter.decrypt(encrypted, function (err, decrypted)
            {
                assert.deepEqual(decrypted, data);
            });
        });
    });
});
```

### Asymmetric operation

```javascript
var priv_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1/3Hc3cuUJwX/otNe\nfr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI+pFtjjLBXD/zJmuL3Afg91J9p\n79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s/\nxHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF+hCdl/syrIh0K\nCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU\n5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQIDAQABAoIBAF2sU/wxvHbwAhQE\npnXVMMcO0thtOodxzBz3JM2xThhWnVDgxCPkAhWq2X0NSm5n9BY5ajwyxYH6heTc\np6lagtxaMONiNaE2W7TqxzMw696vhnYyL+kH2e9+owEoKucXz4QYatqsJIQPb2vM\n0h+DfFAgUvNgYNZ2b9NBsLn9oBImDfYueHyqpRGTdX5urEVtmQz029zaC+jFc7BK\nY6qBRSTwFwnVgE+Td8UgdrO3JQ/0Iwk/lkphnhls/BYvdNC5O8oEppozNVmMV8jm\n61K+agOh1KD8ky60iQFjo3VdFpUjI+W0+sYiYpDb4+Z9OLOTK/5J2EBAGim9siyd\ngHspx+UCgYEA9+t5Rs95hG9Q+6mXn95hYduPoxdFCIFhbGl6GBIGLyHUdD8vmgwP\ndHo7Y0hnK0NyXfue0iFBYD94/fuUe7GvcXib93heJlvPx9ykEZoq9DZnhPFBlgIE\nSGeD8hClazcr9O99Fmg3e7NyTuVou+CIublWWlFyN36iamP3a08pChsCgYEA6gvT\npi/ZkYI1JZqxXsTwzAsR1VBwYslZoicwGNjRzhvuqmqwNvK17dnSQfIrsC2VnG2E\nUbE5EIAWbibdoL4hWUpPx5Tl096OjC3qBR6okAxbVtVEY7Rmv7J9RwriXhtD1DYp\neBvo3eQonApFkfI8Lr2kuKGIgwzkZ72QLXsKJiMCgYBZXBCci0/bglwIObqjLv6e\nzQra2BpT1H6PGv2dC3IbLvBq7hN0TQCNFTmusXwuReNFKNq4FrB/xqEPusxsQUFh\nfv2Il2QoI1OjUE364jy1RZ7Odj8TmKp+hoEykPluybYYVPIbT3kgJy/+bAXyIh5m\nAv2zFEQ86HIWMu4NSb0bHQKBgETEZNOXi52tXGBIK4Vk6DuLpRnAIMVl0+hJC2DB\nlCOzIVUBM/VxKvNP5O9rcFq7ihIEO7SlFdc7S1viH4xzUOkjZH2Hyl+OLOQTOYd3\nkp+AgfXpg8an4ujAUP7mu8xaxns7zsNzr+BCgYwXmIlhWz2Aiz2UeL/IsfOpRwuV\n801xAoGADQB84MJe/X8xSUZQzpn2KP/yZ7C517qDJjComGe3mjVxTIT5XAaa1tLy\nT4mvpSeYDJkBD8Hxr3fB1YNDWNbgwrNPGZnUTBNhxIsNLPnV8WySiW57LqVXlggH\nvjFmyDdU5Hh6ma4q+BeAqbXZSJz0cfkBcBLCSe2gIJ/QJ3YJVQI=\n-----END RSA PRIVATE KEY-----";
var pub_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qiw8PWs7PpnnC2BUEoD\nRcwXF8pq8XT1/3Hc3cuUJwX/otNefr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB\n3sI+pFtjjLBXD/zJmuL3Afg91J9p79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu\n89d2V5x02aXB9LqdXkPwiO0eR5s/xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8U\nVXNPJnQAfaiKazF+hCdl/syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKI\nLwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpj\nsQIDAQAB\n-----END PUBLIC KEY-----";

Crypt.make(priv_pem, function (err, signer)
{
    signer.sign(data, function (err, signed)
    {
        Crypt.make(pub_pem, function (err, verifier)
        {
            verifier.verify(signed, function (err, verified)
            {
                assert.deepEqual(verified, data);
            });
        });
    });
});

Crypt.make(pub_pem, function (err, encrypter)
{
    encrypter.encrypt(data, function (err, encrypted)
    {
        Crypt.make(priv_pem, function (err, decrypter)
        {
            decrypter.decrypt(encrypted, function (err, decrypted)
            {
                assert.deepEqual(decrypted, data);
            });
        });
    });
});
```

### Passwords

```javascript
var pw_info = { password: 'P@ssW0rd!', iterations: 10000 };

Crypt.make(pw_info, function (err, signer)
{
    signer.sign(data, function (err, signed)
    {
        var salted = Object.create(pw_info);
        salted.salt = this.get_key().salt;
        Crypt.make(salted, function (err, verifier)
        {
            verifier.verify(signed, function (err, verified)
            {
                assert.deepEqual(verified, data);
            });
        });
    });
});

Crypt.make(pw_info, function (err, encrypter)
{
    encrypter.encrypt(data, function (err, encrypted)
    {
        var salted = Object.create(pw_info);
        salted.salt = this.get_key().salt;
        Crypt.make(salted, function (err, decrypter)
        {
            decrypter.decrypt(encrypted, function (err, decrypted)
            {
                assert.deepEqual(decrypted, data);
            });
        });
    });
});
```

### Conditional operation

```javascript
Crypt.make('some key', function (err, signer)
{
    signer.maybe_sign(false, data, function (err, signed)
    {
        assert.equal(signed.signed, false);
        Crypt.make(this.get_key(), function (err, verifier)
        {
            verifier.maybe_verify(signed, function (err, verified)
            {
                assert.deepEqual(verified, data);
            });
        });
    });
});

Crypt.make(crypto.randomBytes(Crypt.get_key_size()), function (err, encrypter)
{
    encrypter.maybe_encrypt(true, data, function (err, encrypted)
    {
        assert.equal(encrypted.encrypted, true);
        Crypt.make(this.get_key(), function (err, decrypter)
        {
            decrypter.maybe_decrypt(encrypted, function (err, decrypted)
            {
                assert.deepEqual(decrypted, data);
            });
        });
    });
});
```

### Dynamic key retrieval

```javascript
var pub_pems = { temperature_sensor0: pub_pem };
var priv_pems = { temperature_sensor0: priv_pem };

Crypt.make().maybe_sign(data, function (err, signed)
{
    assert.equal(signed.signed, true);
    Crypt.make().maybe_verify(signed, function (err, verified)
    {
        assert.deepEqual(verified, data);
    }, function (cb, device_id)
    {
        cb(null, pub_pems[device_id]);
    });
}, function (device_id, cb)
{
    cb(null, priv_pems[device_id], device_id);
}, data.device_id);

Crypt.make().maybe_encrypt(data, function (err, encrypted)
{
    assert.equal(encrypted.encrypted, true);
    Crypt.make().maybe_decrypt(encrypted, function (err, decrypted)
    {
        assert.deepEqual(decrypted, data);
    }, function (cb, device_id)
    {
        cb(null, priv_pems[device_id]);
    });
}, function (device_id, cb)
{
    cb(null, pub_pems[device_id], device_id);
}, data.device_id);
```

### Sign-encrypt-sign

```javascript
Crypt.sign_encrypt_sign(priv_pem, pub_pem, data, function (err, data_out)
{
    Crypt.verify_decrypt_verify(priv_pem, pub_pem, data_out, function (err, data_in)
    {
        assert.deepEqual(data_in, data);
    });
});
```

### JSON-less encoding

```javascript
Crypt.make('some signing key', { json: false }, function (err, signer)
{
    signer.sign(new Buffer('"hello"'), function (err, signed)
    {
        this.verify(signed, function (err, verified)
        {
            assert.equal(verified, '"hello"');
        });
    });
});
```

## Licence

[MIT](LICENCE)

## Tests

```shell
grunt test
```

## Lint

```shell
grunt lint
```

## Code Coverage

```shell
grunt coverage
```

[Instanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://githubraw.herokuapp.com/davedoesdev/simple-crypt/master/coverage/lcov-report/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/simple-crypt).

## Benchmarks

```shell
grunt bench
```

Here are some results on a laptop with an Intel Core i5-3210M 2.5Ghz CPU and 6Gb RAM running Ubuntu 13.10.

In the tables, __fast__ is the normal simple-crypt Node.js code wrapper and __slow__ is the browser code _running on Node.js_ (not in a browser).

derive_key_from_password x10|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|68|6,798,449|-
slow|21,970|2,197,037,726|32,217

encrypt_decrypt_asymmetric x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|2,899|2,899,138|-
slow|131,420|131,419,631|4,433

encrypt_decrypt_symmetric x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|422|421,697|-
slow|59,989|59,989,311|14,126

load_rsa_privkey x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|44|44,325|-
slow|225|224,776|407

sign_verify_asymmetric x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|2,843|2,843,213|-
slow|520,668|520,668,069|18,213

sign_verify_symmetric x1,000|total (ms)|average (ns)| diff (%)
:--|--:|--:|--:
fast|347|347,185|-
slow|3,130|3,129,778|801

# API

<a name="tableofcontents"></a>


## Create
- <a name="toc_cryptmakekey-options-cb"></a><a name="toc_crypt"></a>[Crypt.make](#cryptmakekey-options-cb)

## Key functions
- <a name="toc_cryptget_key_size"></a>[Crypt.get_key_size](#cryptget_key_size)
- <a name="toc_cryptparse_keykey-cb"></a>[Crypt.parse_key](#cryptparse_keykey-cb)
- <a name="toc_cryptprototypeget_key"></a><a name="toc_cryptprototype"></a>[Crypt.prototype.get_key](#cryptprototypeget_key)

## Encryption
- <a name="toc_cryptprototypeencryptdata-iv-cb"></a>[Crypt.prototype.encrypt](#cryptprototypeencryptdata-iv-cb)
- <a name="toc_cryptprototypedecryptdata-cb"></a>[Crypt.prototype.decrypt](#cryptprototypedecryptdata-cb)

## Signing
- <a name="toc_cryptprototypesigndata-cb"></a>[Crypt.prototype.sign](#cryptprototypesigndata-cb)
- <a name="toc_cryptprototypeverifydata-cb"></a>[Crypt.prototype.verify](#cryptprototypeverifydata-cb)

## Sign-encrypt-sign
- <a name="toc_cryptsign_encrypt_signsigning_key-encryption_key-data-iv-cb"></a>[Crypt.sign_encrypt_sign](#cryptsign_encrypt_signsigning_key-encryption_key-data-iv-cb)
- <a name="toc_cryptverify_decrypt_verifydecryption_key-verifying_key-data-cb"></a>[Crypt.verify_decrypt_verify](#cryptverify_decrypt_verifydecryption_key-verifying_key-data-cb)

## Conditional and dynamic key operations
- <a name="toc_cryptprototypemaybe_encryptencrypt-data-cb-get_key"></a>[Crypt.prototype.maybe_encrypt](#cryptprototypemaybe_encryptencrypt-data-cb-get_key)
- <a name="toc_cryptprototypemaybe_decryptdata-cb-get_key"></a>[Crypt.prototype.maybe_decrypt](#cryptprototypemaybe_decryptdata-cb-get_key)
- <a name="toc_cryptprototypemaybe_signsign-data-cb-get_key"></a>[Crypt.prototype.maybe_sign](#cryptprototypemaybe_signsign-data-cb-get_key)
- <a name="toc_cryptprototypemaybe_verifydata-cb-get_key"></a>[Crypt.prototype.maybe_verify](#cryptprototypemaybe_verifydata-cb-get_key)

-----

<a name="crypt"></a>

## Crypt.make([key], [options], [cb])

> Create a new `Crypt` object which can be used to sign, verify, encrypt and decrypt data.

**Parameters:**

- `{String | Buffer | Object} [key]` Optional key to use for operations using this object.


  - If you pass a string which looks like it's PEM-encoded then it will be loaded as a RSA key. Otherwise, strings should be binary encoded.

  - If you pass an object then its `password`, `iterations` and optional `salt` properties will be used to derive a key using PBKDF2-SHA1. If you don't supply a salt then a random one is created. You can also supply an optional `progress` property, which must be a function and is called with the percentage completion as the key is derived.

  - Omit the key (or pass `undefined`) if you intend to use one of the [dynamic key retrieval](#conditional-and-dynamic-key-operations) methods.


- `{Object} [options]` Optional settings:


  - `{Boolean} json` Whether to JSON encode and decode data. Default is `true`.

  - `{Boolean} check` Whether to add a checksum to encrypted data and verify it when decrypting data. Default is `true`.

  - `{Boolean} pad` Whether to automatically pad encrypted data (using PKCS#7) to a multiple of the AES block size (16 bytes). Default is `true`.


- `{Function} [cb]` Optional function called with the `Crypt` object. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Crypt} crypt` The `Crypt` object. `key` (above) is parsed using [parse_key](#cryptparse_keykey-cb) and is available using [get_key](#cryptprototypeget_key).


**Return:**

`{Crypt}` The `Crypt` object. It will have no key until key parsing is complete and `cb` is called.

<sub>Go: [TOC](#tableofcontents) | [Crypt](#toc_crypt)</sub>

## Crypt.get_key_size()

> Get the size (in bytes) of symmetric encryption keys. Use this value when creating keys for use with [Crypt.prototype.encrypt](#cryptprototypeencryptdata-iv-cb) and [Crypt.prototype.decrypt](#cryptprototypedecryptdata-cb).

**Return:**

`{Number}` Encryption key size.

<sub>Go: [TOC](#tableofcontents) | [Crypt](#toc_crypt)</sub>

## Crypt.parse_key(key, cb)

> Parse a key. Call this if you want to use the same key for multiple `Crypt` objects but only incur the cost of parsing it once.

**Parameters:**

- `{String | Buffer | Object} key` Key to parse. See the `key` parameter of [Crypt.make](#cryptmakekey-options-cb).



- `{Function} cb` Function called with the parsed key. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{String|Buffer|Object} key` Parsed key. You can pass this to [Crypt.make](#cryptmakekey-options-cb). If the key looks like a PEM-encoded RSA key then an internal RSA key object is returned. If the key is an object (with `password`, `iterations` and optional `salt` properties) then an object with the following properties is returned:

    - `{Object} key` An AES encryption key derived using PBKDF2-SHA-1.

    - `{Buffer|String} salt` Binary-encoded salt value which was used to derive `key`.

<sub>Go: [TOC](#tableofcontents) | [Crypt](#toc_crypt)</sub>

<a name="cryptprototype"></a>

## Crypt.prototype.get_key()

> Get the key being used by this `Crypt` object.

**Return:**

`{Object | Buffer | String}` The key. This could be a `Buffer`, binary-encoded string, internal RSA key object or an object containing a key derived from a password (see [parse_key](#cryptparse_keykey-cb)).

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.encrypt(data, [iv], cb)

> Encrypt data using AES-128-CBC and the key you passed to [Crypt.make](#cryptmakekey-options-cb) when you created this object. If you passed a (PEM-encoded) RSA public key then a random AES key is created and the public key is used to encrypt it (using RSAES-OAEP). The encrypted AES key is made available along with the encrypted data (see below).

**Parameters:**

- `{Object | Buffer | String} data` The data to be encrypted.


  - If you didn't pass `options.json` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the data will be JSON-serialized before it's encrypted. Otherwise, it must be a `Buffer` or binary-encoded string.

  - If you didn't pass `options.check` as `false` to [Crypt.make](#cryptmakekey-options-cb) then a SHA-256 checksum is prepended to the data before it's encrypted.

  - If you didn't pass `options.pad` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the data will be padded to a multiple of 16 bytes.


- `{Buffer | String} [iv]` Optional initialisation vector (salt) to use for AES encryption. If not supplied, a random one is created.



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.
  - `{Object} result` Result of the encryption. Typically you would JSON serialize this for transmission. It has the following properties:

    - `{String} iv` Base64-encoded initialisation vector used for the encryption.
    - `{String} data` Base64-encoded encrypted data. 

    - `{String} ekey` Base64-encoded encrypted AES key (only present when using RSA public key -- see above).

    - `{Number} version` Internal version number for future compatibility checking.

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.decrypt(data, cb)

> Decrypt data using AES-128-CBC and the key you passed to [Crypt.make](#cryptmakekey-options-cb) when you created this object. If you passed a (PEM-encoded) RSA private key then an `ekey` property is expected to be present on the `data` parameter (below). The private key is used to decrypt the `ekey` in order to obtain the AES key.

**Parameters:**

- `{Object} data` A result object returned by [encrypt](#cryptprototypeencryptdata-iv-cb). You may have received this from another party, for instance.


  - If you didn't pass `options.json` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the data will be JSON-parsed after it's encrypted. Otherwise, you'll receive a `Buffer` (on Node.js) or binary-encoded string.

  - If you didn't pass `options.check` as `false` to [Crypt.make](#cryptmakekey-options-cb) then a SHA-256 checksum is expected to be prepended to the decrypted data. The checksum is verified against the rest of the decrypted data.

  - If you didn't pass `options.pad` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the decrypted data is expected to be padded to a multiple of 16 bytes and will be unpadded automatically.


- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Object|Buffer|String} data` The decrypted data.

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.sign(data, cb)

> Sign a SHA-256 hash of some data using the key you passed to [Crypt.make](#cryptmakekey-options-cb) when you created this object. If you passed a (PEM-encoded) RSA private key then the hash is signed using RSASSA-PSS. Otherwise, HMAC-SHA-256 is used to sign the data.

**Parameters:**

- `{Object | Buffer | String} data` The data to be signed.


  - If you didn't pass `options.json` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the data will be JSON-serialized before it's encrypted. Otherwise, it must be a `Buffer` or binary-encoded string.


- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.
  - `{Object} result` Result of signing the data. Typically you would JSON serialize this for transmission. It has the following properties:

    - `{String} data` The data that was signed (Base64-encoded).

    - `{String} signature` Base64-encoded signed hash of the data.

    - `{Number} version` Internal version number for future compatibility checking.

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.verify(data, cb)

> Verify a signature by comparing it to a signed SHA-256 hash of some data. The signed hash is generated using the key you passed to [Crypt.make](#cryptmakekey-options-cb) when you created this object. If you passed a (PEM-encoded) RSA public key then the hash is signed using RSASSA-PSS. Otherwise HMAC is used.

**Parameters:**

- `{Object} data` A result object returned by [sign](#cryptprototypesigndata-cb). You may have received this from another party, for instance.


  - If you didn't pass `options.json` as `false` to [Crypt.make](#cryptmakekey-options-cb) then the data will be JSON-parsed after it's verified. Otherwise, you'll receive a `Buffer` (on Node.js) or binary-encoded string.


- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Object|Buffer|String} data` The verified data.

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.sign_encrypt_sign(signing_key, encryption_key, data, [iv], cb)

> Sign then encrypt then sign data. Convenience function which creates two `Crypt` objects, calls [sign](#cryptprototypesigndata-cb) on the first, plumbs the result into [encrypt](#cryptprototypeencryptdata-iv-cb) on the second and then plumbs the result from that into [sign](#cryptprototypesigndata-cb) on the first again. See [this article](http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html) for a discussion of why just sign then encrypt isn't good enough.

**Parameters:**

- `{String} signing_key` Key to use for signing the data.



- `{String} encryption_key` Key to use for encrypting the data and signature.



- `{Object | Buffer | String} data` The data to be signed and encrypted.



- `{Buffer | String} [iv]` Optional initialisation vector (salt) to use for encryption. If not supplied, a random one is created.



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.
  - `{Object} result` Result of signing and encrypting the data. See the description of `cb` for [sign](#cryptprototypesigndata-cb).

<sub>Go: [TOC](#tableofcontents) | [Crypt](#toc_crypt)</sub>

## Crypt.verify_decrypt_verify(decryption_key, verifying_key, data, cb)

> Verify then decrypt then verify data. Convenience function which creates two `Crypt` objects, calls [verify](#cryptprototypeverifydata-cb) on the first, plumbs the result into [decrypt](#cryptprototypedecryptdata-cb) on the second and then plumbs the result from that into [verify](#cryptprototypeverifydata-cb) on the first again.

**Parameters:**

- `{String} decryption_key` Key to use for decrypting the data and signature.



- `{String} verifying_key` Key to use for verifying the signature.



- `{Object} data` A result object returned by [sign_encrypt_sign](#cryptsign_encrypt_signsigning_key-encryption_key-data-iv-cb).



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Object|Buffer|String} data` The decrypted and verified data.

<sub>Go: [TOC](#tableofcontents) | [Crypt](#toc_crypt)</sub>

## Crypt.prototype.maybe_encrypt(encrypt, data, cb, [get_key])

> Conditionally encrypt data using [encrypt](#cryptprototypeencryptdata-iv-cb).

**Parameters:**

- `{Boolean} encrypt` Whether to encrypt the data.



- `{Object | Buffer | String} data` The data to encrypt.



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Object} result` Result object with the following properties:

    - `{Boolean} encrypted` Whether the data was encrypted.

    - `{Object} data` Encryption result (data, initialisation vector etc) if the data was encrypted, otherwise the data.

    - `{Object} [key_data]` If the data was encrypted and `get_key` was called (see below) then this is the key data returned by `get_key`.


- `{Function} [get_key]` Optional function to call in order to get the encryption key. You must supply this if you didn't supply a key when creating the `Crypt` object. `get_key` is called with the following arguments:


  - The arguments to `maybe_encrypt` that follow `get_key` (if any).

  - `{Function} got_key` Function to call with the key. You should call it with the following arguments:

    - `{Object} err` If an error occurred then details of the error, otherwise `null`.

    - `{Object|Buffer|String} key` The encryption key. If this is a falsey value then the data won't be encrypted.

    - `{Object} [key_data]` Optional metadata for the key. This is included in the result (see above).

    - `{Buffer|String} [iv]` Optional initialisation vector.

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.maybe_decrypt(data, cb, [get_key])

> Conditionally decrypt data using [decrypt](#cryptprototypedecryptdata-cb).

**Parameters:**

- `{Object} data` A result object returned by [maybe_encrypt](#cryptprototypemaybe_encryptencrypt-data-cb-get_key).



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an Error occurred then details of the error, otherwise `null`.

  - `{Object|Buffer|String} data` If the data was encrypted then the decrypted data otherwise the data.


- `{Function} [get_key]` Optional function to call in order to get the encryption key. You must supply this if you didn't supply a key when creating the `Crypt` object. `get_key` is called with the following arguments:


  - The arguments to `maybe_decrypt` that follow `get_key` (if any).

  - `{Function} got_key` Function to call with the key. You should call it with the following arguments:

    - `{Object} err` If an error occurred then details of the error, otherwise `null`.

    - `{Object|Buffer|String} key` The decryption key.

  - `{Object} [key_data]` Metadata for the key which was supplied in [maybe_encrypt](#cryptprototypemaybe_encryptencrypt-data-cb-get_key) (if any).

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.maybe_sign(sign, data, cb, [get_key])

> Conditionally sign data using [sign](#cryptprototypesigndata-cb).

**Parameters:**

- `{Boolean} sign` Whether to sign the data.



- `{Object | Buffer | String} data` The data to sign.



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{Object} result` Result object with the following properties:

    - `{Boolean} signed` Whether the data was signed.

    - `{Object} data` Signing result (data, signature etc) if the data was signed, otherwise the data.

    - `{Object} [key_data]` If the data was signed and `get_key` was called (see below) then this is the key data returned by `get_key`.


- `{Function} [get_key]` Optional function to call in order to get the signing key. You must supply this if you didn't supply a key when creating the `Crypt` object. `get_key` is called with the following arguments:


  - The arguments to `maybe_sign` that follow `get_key` (if any).

  - `{Function} got_key` Function to call with the key. You should call it with the following arguments:

    - `{Object} err` If an error occurred then details of the error, otherwise `null`.

    - `{Object|Buffer|String} key` The signing key. If this is a falsey value then the data won't be signed.

    - `{Object} [key_data]` Optional metadata for the key. This is included in the result (see above).

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

## Crypt.prototype.maybe_verify(data, cb, [get_key])

> Conditionally verify data using [verify](#cryptprototypeverifydata-cb).

**Parameters:**

- `{Object} data` A result object returned by [maybe_sign](#cryptprototypemaybe_signsign-data-cb-get_key).



- `{Function} cb` Function called with the result. It's passed the following arguments:


  - `{Object} err` If an Error occurred then details of the error, otherwise `null`.

  - `{Object|Buffer|String} data` If the data was signed then the verified data otherwise the data.


- `{Function} [get_key]` Optional function to call in order to get the verifying key. You must supply this if you didn't supply a key when creating the `Crypt` object. `get_key` is called with the following arguments:


  - The arguments to `maybe_verify` that follow `get_key` (if any).

  - `{Function} got_key` Function to call with the key. You should call it with the following arguments:

    - `{Object} err` If an error occurred then details of the error, otherwise `null`.

    - `{Object|Buffer|String} key` The verifying key.

  - `{Object} [key_data]` Metadata for the key which was supplied in [maybe_sign](#cryptprototypemaybe_signsign-data-cb-get_key) (if any).

<sub>Go: [TOC](#tableofcontents) | [Crypt.prototype](#toc_cryptprototype)</sub>

_&mdash;generated by [apidox](https://github.com/codeactual/apidox)&mdash;_
