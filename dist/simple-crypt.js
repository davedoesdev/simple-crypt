/*global require: false,
         slowAES: false,
         window: false,
         exports: false,
         rstr_hmac_sha256: false,
         b64tohex: false,
         hex2b64: false,
         rstr_sha256: false,
         Uint8Array: false,
         escape: false,
         unescape: false,
         PBKDF2: false,
         rstr_sha1: false,
         Buffer: false,
         RSAKey: false,
         process: false */
/*jslint nomen: true */

// Simple symmetric and asymmetric crypto.
// Note: Keep an eye on http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

var SHA1_SIZE = 20,
    SHA256_SIZE = 32,
    AES_BLOCK_SIZE = 16,
    AES_128_KEY_SIZE = 16,

Crypt = function (parsed_key, options)
{
    "use strict";

    this.key = parsed_key;

    options = options || {};

    this.options = {};
    this.options.json = options.json !== false;
    this.options.check = options.check !== false;
    this.options.pad = options.pad !== false;
    this.options.custom = options.custom;

    this.encoding = options.base64 !== false ? 'base64' : undefined;
};

Crypt.make = function (key, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = {};
    }

    if (!cb)
    {
        cb = key;
        key = undefined;
    }

    if (typeof cb !== 'function')
    {
        options = cb;
        cb = undefined;
    }

    var This = this,
        crypt = new This(undefined, options);

    This.parse_key(key, function (err, parsed_key)
    {
        if (err)
        {
            cb(err);
            return;
        }

        crypt.key = parsed_key;

        if (cb)
        {
            cb(null, crypt);
        }
    });

    return crypt;
};

Crypt.get_version = function ()
{
    "use strict";
    return 1;
};

Crypt.get_key_size = function ()
{
    "use strict";
    return AES_128_KEY_SIZE;
};

Crypt.prototype.get_key = function ()
{
    "use strict";
    return this.key;
};

Crypt.prototype.check_version = function (data, f)
{
    "use strict";

    if (data.version > Crypt.get_version())
    {
        f.call(this, 'unsupported version');
        return false;
    }
    
    return true;
};

Crypt.prototype.maybe_encrypt = function (arg_encrypt,
                                          arg_data,
                                          arg_f,
                                          arg_get_key)
{
    "use strict";

    var ths = this, encrypt, data, f, get_key, get_key_data,

    encrypted = function (err, edata, key_data)
    {
        if (err)
        {
            f.call(this, err);
        }
        else
        {
            f.call(this, null, { encrypted: true, data: edata, key_data: key_data });
        }
    },
    
    not_encrypted = function ()
    {
        f.call(this, null, { encrypted: false, data: data });
    };
    
    if (typeof arg_data === 'function')
    {
        get_key_data = Array.prototype.slice.call(arguments, 3);
        get_key = arg_f;
        f = arg_data;
        data = arg_encrypt;
        encrypt = (get_key !== undefined) || this.key;
    }
    else
    {
        get_key_data = Array.prototype.slice.call(arguments, 4);
        get_key = arg_get_key;
        f = arg_f;
        data = arg_data;
        encrypt = arg_encrypt;
    }

    if (encrypt)
    {
        if (get_key !== undefined)
        {
            get_key_data.push(function (err, key, key_data, iv)
            {
                if (err)
                {
                    f.call(ths, err);
                }
                else if (key)
                {
                    Crypt.make(key, ths.options, function (err, crypt)
                    {
                        if (err)
                        {
                            f.call(ths, err);
                        }
                        else
                        {
                            crypt.encrypt(data, iv, function (err, data)
                            {
                                encrypted.call(this, err, data, key_data);
                            });
                        }
                    });
                }
                else
                {
                    not_encrypted.call(ths);
                }
            });

            get_key.apply(this, get_key_data);
        }
        else
        {
            this.encrypt(data, encrypted);
        }
    }
    else
    {
        not_encrypted.call(this);
    }
};

Crypt.prototype.maybe_decrypt = function (data, f, get_key)
{
    "use strict";

    if (data.encrypted)
    {
        if (get_key !== undefined)
        {
            var ths = this,
                get_key_data = Array.prototype.slice.call(arguments, 3);

            get_key_data.push(function (err, key)
            {
                if (err)
                {
                    f.call(ths, err);
                }
                else
                {
                    Crypt.make(key, ths.options, function (err, crypt)
                    {
                        if (err)
                        {
                            f.call(ths, err);
                        }
                        else
                        {
                            crypt.decrypt(data.data, f);
                        }
                    });
                }
            });

            get_key_data.push(data.key_data);

            get_key.apply(this, get_key_data);
        }
        else
        {
            this.decrypt(data.data, f);
        }
    }
    else
    {
        f.call(this, null, data.data);
    }
};

Crypt.prototype.maybe_sign = function (arg_sign, arg_data, arg_f, arg_get_key)
{
    "use strict";

    var ths = this, sign, data, f, get_key, get_key_data,

    signed = function (err, sdata, key_data)
    {
        if (err)
        {
            f.call(this, err);
        }
        else
        {
            f.call(this, null, { signed: true, data: sdata, key_data: key_data });
        }
    },

    not_signed = function ()
    {
        f.call(this, null, { signed: false, data: data });
    };

    if (typeof arg_data === 'function')
    {
        get_key_data = Array.prototype.slice.call(arguments, 3);
        get_key = arg_f;
        f = arg_data;
        data = arg_sign;
        sign = (get_key !== undefined) || this.key;
    }
    else
    {
        get_key_data = Array.prototype.slice.call(arguments, 4);
        get_key = arg_get_key;
        f = arg_f;
        data = arg_data;
        sign = arg_sign;
    }

    if (sign)
    {
        if (get_key !== undefined)
        {
            get_key_data.push(function (err, key, key_data)
            {
                if (err)
                {
                    f.call(ths, err);
                }
                else if (key)
                {
                    Crypt.make(key, ths.options, function (err, crypt)
                    {
                        if (err)
                        {
                            f.call(ths, err);
                        }
                        else
                        {
                            crypt.sign(data, function (err, data)
                            {
                                signed.call(this, err, data, key_data);
                            });
                        }
                    });
                }
                else
                {
                    not_signed.call(ths);
                }
            });

            get_key.apply(this, get_key_data);
        }
        else
        {
            this.sign(data, signed);
        }
    }
    else
    {
        not_signed.call(this);
    }
};

Crypt.prototype.maybe_verify = function (data, f, get_key)
{
    "use strict";

    if (data.signed)
    {
        if (get_key !== undefined)
        {
            var ths = this,
                get_key_data = Array.prototype.slice.call(arguments, 3);

            get_key_data.push(function (err, key)
            {
                if (err)
                {
                    f.call(ths, err);
                }
                else
                {
                    Crypt.make(key, ths.options, function (err, crypt)
                    {
                        if (err)
                        {
                            f.call(ths, err);
                        }
                        else
                        {
                            crypt.verify(data.data, f);
                        }
                    });
                }
            });

            get_key_data.push(data.key_data);

            get_key.apply(this, get_key_data);
        }
        else
        {
            this.verify(data.data, f);
        }
    }
    else
    {
        f.call(this, null, data.data);
    }
};

Crypt.sign_encrypt_sign = function (signing_key, encryption_key, data, iv, f)
{
    "use strict";

    if (!f)
    {
        f = iv;
        iv = null;
    }

    var This = this;

    This.make(signing_key, function (err, signer)
    {
        if (err)
        {
            f(err);
            return;
        }

        This.make(encryption_key, function (err, encrypter)
        {
            if (err)
            {
                f(err);
                return;
            }

            signer.sign(data, function (err, sv)
            {
                if (err)
                {
                    f(err);
                    return;
                }

                encrypter.encrypt(sv, iv, function (err, ev)
                {
                    if (err)
                    {
                        f(err);
                        return;
                    }

                    signer.sign(ev, f);
                });
            });
        });
    });
};

Crypt.verify_decrypt_verify = function (decryption_key, verifying_key, data, f)
{
    "use strict";

    var This = this;

    This.make(verifying_key, function (err, verifier)
    {
        if (err)
        {
            f(err);
            return;
        }

        This.make(decryption_key, function (err, decrypter)
        {
            if (err)
            {
                f(err);
                return;
            }

            verifier.verify(data, function (err, vv)
            {
                if (err)
                {
                    f(err);
                    return;
                }

                decrypter.decrypt(vv, function (err, dv)
                {
                    if (err)
                    {
                        f(err);
                        return;
                    }

                    verifier.verify(dv, f);
                });
            });
        });
    });
};

Crypt.encrypt_stream = function (key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }

    this.make(key,
    {
        base64: false,
        json: false
    }, function (err, encrypter)
    {
        if (err)
        {
            return cb(err);
        }

        var Transform = require('stream').Transform,
            t = new Transform(),
            frame = require('frame-stream'),
            out_s = frame.encode(options),
            crypto = require('crypto'),
            prev_hash;

        t._transform = function (chunk, encoding, callback)
        {
            var ths = this;

            encrypter.encrypt(Buffer.concat(
                    prev_hash ? [new Buffer([1]), prev_hash, chunk] :
                                [new Buffer([0]), chunk]),
            function (err, ev)
            {
                if (err)
                {
                    return callback(err);
                }

                var hash = crypto.createHash('sha256');

                ths.push(ev.iv);
                hash.update(ev.iv);

                ths.push(ev.data);
                hash.update(ev.data);

                var buf = new Buffer(4);
                buf.writeUInt32BE(ev.version, 0, true);
                ths.push(buf);
                hash.update(buf);

                buf = Buffer.concat(
                    ev.ekey ? [new Buffer([1]), ev.ekey] :
                              [new Buffer([0])]);
                ths.push(buf);
                hash.update(buf);

                prev_hash = hash.digest();

                callback();
            });
        };

        t.pipe(out_s);
        s.pipe(t);

        cb(null, out_s);
    });
};

Crypt.decrypt_stream = function (key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }
 
    this.make(key,
    {
        base64: false,
        json: false
    }, function (err, decrypter)
    {
        if (err)
        {
            return cb(err);
        }

        var Transform = require('stream').Transform,
            t = new Transform(),
            frame = require('frame-stream'),
            in_s = frame.decode(options),
            crypto = require('crypto'),
            hash,
            prev_hash,
            state = 0,
            ev;

        t._transform = function (chunk, encoding, callback)
        {
            var err;

            switch (state)
            {
                case 0:
                    hash = crypto.createHash('sha256');
                    ev = { iv: chunk };
                    state = 1;
                    break;

                case 1:
                    ev.data = chunk;
                    state = 2;
                    break;

                case 2:
                    if (chunk.length !== 4)
                    {
                        err = callback(new Error('wrong length'));
                        break;
                    }
                    ev.version = chunk.readUInt32BE(0, true);
                    state = 3;
                    break;

                case 3:
                    if (chunk.length < 1)
                    {
                        err = callback(new Error('wrong length'));
                        break;
                    }
                    if (chunk[0] == 1)
                    {
                        ev.ekey = chunk.slice(1);
                    }
                    state = 4;
                    break;

                default:
                    err = new Error('unexpected state');
                    break;
            }

            if (err)
            {
                state = 0;
                return callback(err);
            }

            if (state > 4)
            {
                state = 0;
                return callback(new Error('unexpected state'));
            }

            hash.update(chunk);

            if (state < 4)
            {
                return callback();
            }

            state = 0;

            decrypter.decrypt(ev, function (err, data)
            {
                if (err)
                {
                    return callback(err);
                }

                if (prev_hash)
                {
                    if (data[0] !== 1)
                    {
                        return callback(new Error('wrong marker'));
                    }

                    if (!buffer_equal(data.slice(1, 1 + SHA256_SIZE),
                                      prev_hash))
                    {
                        return callback(new Error('wrong order'));
                    }
                    
                    data = data.slice(1 + SHA256_SIZE);
                }
                else
                {
                    if (data[0] !== 0)
                    {
                        return callback(new Error('wrong marker'));
                    }

                    data = data.slice(1);
                }

                prev_hash = hash.digest();

                callback(null, data);
            });
        };

        in_s.pipe(t);
        s.pipe(in_s);

        cb(null, t);
    });
};

Crypt.sign_stream = function (key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }

    this.make(key,
    {
        base64: false,
        json: false
    }, function (err, signer)
    {
        if (err)
        {
            return cb(err);
        }

        var Transform = require('stream').Transform,
            t = new Transform(),
            frame = require('frame-stream'),
            out_s = frame.encode(options),
            crypto = require('crypto'),
            prev_hash;

        t._transform = function (chunk, encoding, callback)
        {
            var ths = this;

            signer.sign(Buffer.concat(
                prev_hash ? [new Buffer([1]), prev_hash, chunk] :
                            [new Buffer([0]), chunk]),
            function (err, sv)
            {
                if (err)
                {
                    return callback(err);
                }

                var hash = crypto.createHash('sha256');

                ths.push(sv.signature);
                hash.update(sv.signature);

                ths.push(sv.data);
                hash.update(sv.data);

                var buf = new Buffer(4);
                buf.writeUInt32BE(sv.version, 0, true);
                ths.push(buf);
                hash.update(buf);

                prev_hash = hash.digest();

                callback();
            });
        };

        t.pipe(out_s);
        s.pipe(t);

        cb(null, out_s);
    });
};

Crypt.verify_stream = function (key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }
 
    this.make(key,
    {
        base64: false,
        json: false
    }, function (err, verifier)
    {
        if (err)
        {
            return cb(err);
        }

        var Transform = require('stream').Transform,
            t = new Transform(),
            frame = require('frame-stream'),
            in_s = frame.decode(options),
            crypto = require('crypto'),
            hash,
            prev_hash,
            state = 0,
            sv;

        t._transform = function (chunk, encoding, callback)
        {
            var err;

            switch (state)
            {
                case 0:
                    hash = crypto.createHash('sha256');
                    sv = { signature: chunk };
                    state = 1;
                    break;

                case 1:
                    sv.data = chunk;
                    state = 2;
                    break;

                case 2:
                    if (chunk.length !== 4)
                    {
                        err = callback(new Error('wrong length'));
                        break;
                    }
                    sv.version = chunk.readUInt32BE(0, true);
                    state = 3;
                    break;

                default:
                    err = new Error('unexpected state');
                    break;
            }

            if (err)
            {
                state = 0;
                return callback(err);
            }

            if (state > 3)
            {
                state = 0;
                return callback(new Error('unexpected state'));
            }

            hash.update(chunk);

            if (state < 3)
            {
                return callback();
            }

            state = 0;

            verifier.verify(sv, function (err, data)
            {
                if (err)
                {
                    return callback(err);
                }

                if (prev_hash)
                {
                    if (data[0] !== 1)
                    {
                        return callback(new Error('wrong marker'));
                    }

                    if (!buffer_equal(data.slice(1, 1 + SHA256_SIZE),
                                      prev_hash))
                    {
                        return callback(new Error('wrong order'));
                    }
                    
                    data = data.slice(1 + SHA256_SIZE);
                }
                else
                {
                    if (data[0] !== 0)
                    {
                        return callback(new Error('wrong marker'));
                    }

                    data = data.slice(1);
				}

                prev_hash = hash.digest();

                callback(null, data);
            });
        };

        in_s.pipe(t);
        s.pipe(in_s);

        cb(null, t);
    });
};

Crypt.sign_encrypt_sign_stream = function (signing_key, encryption_key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }

    var This = this;

    This.sign_stream(signing_key, s, options, function (err, ss)
    {
        if (err)
        {
            return cb(err);
        }

        This.encrypt_stream(encryption_key, ss, options, function (err, es)
        {
            if (err)
            {
                return cb(err);
            }

            This.sign_stream(signing_key, es, options, cb);
        });
    });
};

Crypt.verify_decrypt_verify_stream = function (decryption_key, verifying_key, s, options, cb)
{
    "use strict";

    if (!cb)
    {
        cb = options;
        options = undefined;
    }

    var This = this;

    This.verify_stream(verifying_key, s, options, function (err, vs)
    {
        if (err)
        {
            return cb(err);
        }

        This.decrypt_stream(decryption_key, vs, options, function (err, ds)
        {
            if (err)
            {
                return cb(err);
            }

            This.verify_stream(verifying_key, ds, options, cb);
        });
    });
};

var SlowCrypt;

if (typeof require === 'function')
{
    var crypto = require('crypto'),
        ursa = require('ursa'),
        // keep an eye out for built-in constant time comparison function:
        // https://github.com/nodejs/node/issues/3043
        buffer_equal = require('buffer-equal-constant-time');

    Crypt.parse_key = function (key, cb)
    {
        "use strict";

        if ((typeof key === 'string') &&
            (key.lastIndexOf('-----BEGIN', 0) === 0))
        {
            if (key.indexOf('PUBLIC KEY') > 0)
            {
                key = ursa.createPublicKey(key, 'utf8');
            }
            else if (key.indexOf('PRIVATE KEY') > 0)
            {
                key = ursa.createPrivateKey(key, '', 'utf8');
            }

            cb(null, key);
        }
        else if (key && key.password)
        {
            var salt = key.salt || crypto.randomBytes(SHA1_SIZE),
                hash;
            
            if (salt.length < SHA1_SIZE)
            {
                hash = crypto.createHash('sha1');
                hash.update(salt);
                salt = hash.digest();
            }

            crypto.pbkdf2(key.password, salt, key.iterations, AES_128_KEY_SIZE,
            function (err, derived_key)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                if (key.progress)
                {
                    key.progress(100);
                }

                cb(null,
                {
                    key: derived_key,
                    salt: salt
                });
            });
        }
        else
        {
            cb(null, key);
        }
    };

    Crypt.prototype.stringify = function (data)
    {
        "use strict";
        return this.options.json ? new Buffer(JSON.stringify(data), 'utf8') : data;
    };

    Crypt.prototype.parse = function (data)
    {
        "use strict";
        return this.options.json ? JSON.parse(data.toString('utf8')) : data;
    };

    Crypt.prototype.encrypt = function (data, iv, f)
    {
        "use strict";

        var key, ekey, iv64, cipher, jdata, edata = [];

        try
        {
            if (!f)
            {
                f = iv;
                iv = null;
            }

            if (this.key.privateEncrypt)
            {
                f.call(this, "can't encrypt using private key");
                return;
            }

            if (this.key.encrypt)
            {
                key = crypto.randomBytes(AES_128_KEY_SIZE);
                ekey = this.key.encrypt(key,
                                        undefined,
                                        this.encoding,
                                        ursa.RSA_PKCS1_OAEP_PADDING);
            }
            else
            {
                key = this.key.key || this.key;
            }

            iv = iv || crypto.randomBytes(AES_BLOCK_SIZE);
            iv64 = this.encoding ? iv.toString(this.encoding) : iv;

            cipher = crypto.createCipheriv('AES-128-CBC', key, iv);
            cipher.setAutoPadding(this.options.pad);

            jdata = this.stringify(data);

            if (this.options.check)
            {
                edata.push(cipher.update(crypto.createHash('sha256')
                                               .update(jdata)
                                               .digest(),
                                         undefined,
                                         this.encoding));
            }

            edata.push(cipher.update(jdata, undefined, this.encoding));
            edata.push(cipher.final(this.encoding));

            if (this.encoding)
            {
                edata = edata.join('');
            }
            else
            {
                edata = Buffer.concat(edata);
            }
        }
        catch (ex)
        {
            f.call(this, ex);
            return;
        }

        f.call(this, null, { iv: iv64, data: edata, ekey: ekey, version: Crypt.get_version() });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var key, decipher, ddata, jdata;

        try
        {
            if (!this.check_version(data, f))
            {
                return;
            }

            if (this.key.decrypt)
            {
                key = this.key.decrypt(data.ekey, this.encoding, undefined, ursa.RSA_PKCS1_OAEP_PADDING);
            }
            else if (!this.key.publicDecrypt)
            {
                key = this.key.key || this.key;
            }
            else
            {
                f.call(this, "can't decrypt using public key");
                return;
            }

            decipher = crypto.createDecipheriv(
                    'AES-128-CBC',
                    key,
                    this.encoding ? new Buffer(data.iv, this.encoding) :
                                    data.iv);
            decipher.setAutoPadding(this.options.pad);

            ddata = decipher.update(data.data, this.encoding);
            ddata = Buffer.concat([ddata, decipher.final()]);

            if (this.options.check)
            {
                jdata = ddata.slice(SHA256_SIZE);

                if (!buffer_equal(crypto.createHash('sha256')
                                        .update(jdata)
                                        .digest(),
                                  ddata.slice(0, SHA256_SIZE)))
                {
                    f.call(this, 'digest mismatch');
                    return;
                }
            }
            else
            {
                jdata = ddata;
            }

            jdata = this.parse(jdata);
        }
        catch (ex)
        {
            f.call(this, ex);
            return;
        }

        f.call(this, null, jdata);
    };

    Crypt.prototype.sign = function (data, f)
    {
        "use strict";

        var jdata, signature;

        try
        {
            jdata = this.stringify(data);

            if (this.key.hashAndSign)
            {
                signature = this.key.hashAndSign('sha256',
                                                 jdata,
                                                 undefined,
                                                 this.encoding,
                                                 true);
            }
            else if (!this.key.encrypt)
            {
                signature = crypto.createHmac('sha256', this.key.key || this.key)
                        .update(jdata)
                        .digest(this.encoding);
            }
            else
            {
                f.call(this, "can't sign using public key");
                return;
            }

            if (this.encoding)
            {
                jdata = jdata.toString(this.encoding);
            }
        }
        catch (ex)
        {
            f.call(this, ex);
            return;
        }

        f.call(this, null, { data: jdata, signature: signature, version: Crypt.get_version() });
    };

    Crypt.prototype.verify = function (data, f)
    {
        "use strict";

        var match, ddata, jdata;

        try
        {
            if (!this.check_version(data, f))
            {
                return;
            }

            ddata = this.encoding ? new Buffer(data.data, this.encoding) :
                                    data.data;

            if (this.key.decrypt)
            {
                f.call(this, "can't verify using private key");
                return;
            }

            if (this.key.hashAndVerify)
            {
                match = this.key.hashAndVerify(
                            'sha256',
                            data.data,
                            data.signature,
                            this.encoding,
                            true);
            }
            else
            {
                match = buffer_equal(crypto.createHmac('sha256',
                                                       this.key.key || this.key)
                                           .update(ddata).digest(),
                                     this.encoding ? new Buffer(data.signature,
                                                                this.encoding) :
                                                     data.signature);
            }

            if (match)
            {
                jdata = this.parse(ddata);
            }
            else
            {
                f.call(this, 'digest mismatch');
                return;
            }
        }
        catch (ex)
        {
            f.call(this, ex);
            return;
        }

        f.call(this, null, jdata);
    };

    SlowCrypt = function ()
    {
        "use strict";
        Crypt.apply(this, arguments);
    };

    SlowCrypt.make = Crypt.make;
    SlowCrypt.get_version = Crypt.get_version;
    SlowCrypt.get_key_size = Crypt.get_key_size;
    SlowCrypt.sign_encrypt_sign = Crypt.sign_encrypt_sign;
    SlowCrypt.verify_decrypt_verify = Crypt.verify_decrypt_verify;
    SlowCrypt.encrypt_stream = Crypt.encrypt_stream;
    SlowCrypt.decrypt_stream = Crypt.decrypt_stream;
    SlowCrypt.sign_stream = Crypt.sign_stream;
    SlowCrypt.verify_stream = Crypt.verify_stream;
    SlowCrypt.sign_encrypt_sign_stream = Crypt.sign_encrypt_sign_stream;
    SlowCrypt.verify_decrypt_verify_stream = Crypt.verify_decrypt_verify_stream;

    SlowCrypt.prototype = Object.create(Crypt.prototype);
}
else
{
    SlowCrypt = Crypt;
}

var get_char_codes = function(s)
{
    "use strict";

    var r = [], i;

    for (i = 0; i < s.length; i += 1)
    {
        r.push(s.charCodeAt(i));
    }

    return r;
};

// from https://github.com/goinstant/buffer-equal-constant-time/blob/master/index.js
var const_time_equal = function (s1, s2)
{
    "use strict";
    if (s1.length !== s2.length)
    {
        return false;
    }
    var i, c = 0;
    for (i = 0; i < s1.length; i += 1)
    {
        /*jslint bitwise: true */
        c |= s1.charCodeAt(i) ^ s2.charCodeAt(i); // XOR
        /*jslint bitwise: false */
    }
    return c === 0;
};

SlowCrypt.parse_key = function (key, cb)
{
    "use strict";

    var rsa_key, salt, pbkdf2;

    if (typeof key === 'string')
    {
        if (key.lastIndexOf('-----BEGIN', 0) === 0)
        {
            if (key.indexOf('PUBLIC KEY') > 0)
            {
                rsa_key = new RSAKey();
                rsa_key.readPublicKeyFromPEMString(key);
                cb(null, rsa_key);
                return;
            }

            if (key.indexOf('PRIVATE KEY') > 0)
            {
                rsa_key = new RSAKey();
                rsa_key.readPrivateKeyFromPEMString(key);
                cb(null, rsa_key);
                return;
            }
        }

        cb(null, get_char_codes(key));
    }
    else if (key && key.password)
    {
        salt = key.salt;

        if (!salt)
        {
            salt = new Uint8Array(SHA1_SIZE);
            window.crypto.getRandomValues(salt);
            salt = String.fromCharCode.apply(String, Array.prototype.slice.call(salt));
        }

        if (salt.length < SHA1_SIZE)
        {
            salt = rstr_sha1(salt);
        }

        pbkdf2 = new PBKDF2(key.password,
                            salt,
                            key.iterations,
                            AES_128_KEY_SIZE);

        pbkdf2.deriveKey(
            key.progress || function () { return undefined; },
            function (derived_key)
            {
                var bytes = [], i;

                for (i = 0; i < derived_key.length; i += 2)
                {
                    bytes.push(parseInt(derived_key.substr(i, 2), 16));
                }

                cb(null,
                {
                    key: bytes,
                    salt: salt
                });
            });
    }
    else
    {
        cb(null, key);
    }
};

SlowCrypt.prototype.stringify = function (data)
{
    "use strict";

    // http://ecmanaut.blogspot.co.uk/2006/07/encoding-decoding-utf8-in-javascript.html
    return this.options.json ? unescape(encodeURIComponent(JSON.stringify(data))) : data;
};

SlowCrypt.prototype.parse = function (data)
{
    "use strict";
    return this.options.json ? JSON.parse(decodeURIComponent(escape(data))) : data;
};

SlowCrypt.prototype.encrypt = function (data, iv, f)
{
    "use strict";

    var key_arr, ekey, iv64, jdata, edata;

    try
    {
        if (!f)
        {
            f = iv;
            iv = undefined;
        }

        if (this.key.isPrivate)
        {
            f.call(this, "can't encrypt using private key");
            return;
        }

        if (this.key.isPublic)
        {
            key_arr = new Uint8Array(AES_128_KEY_SIZE);
            window.crypto.getRandomValues(key_arr);
            ekey = (this.encoding ? hex2b64 : hextorstr)(this.key.encryptOAEP(String.fromCharCode.apply(String, Array.prototype.slice.call(key_arr))/*, rstr_sha256, 32*/));
        }
        else
        {
            key_arr = this.key.key || this.key;
        }

        if (!iv)
        {
            iv = new Uint8Array(AES_BLOCK_SIZE);
            window.crypto.getRandomValues(iv);
        }

        iv64 = this.encoding ? window.btoa(String.fromCharCode.apply(String, Array.prototype.slice.call(iv))) : iv;

        jdata = this.stringify(data);

        if (!this.options.pad)
        {
            slowAES._padBytesIn_save = slowAES.padBytesIn;
            slowAES.padBytesIn = function (data)
            {
                return data;
            };
        }

        if (this.options.check)
        {
            if (typeof jdata !== 'string')
            {
                jdata = String.fromCharCode.apply(String, jdata);
            }

            jdata = get_char_codes(rstr_sha256(jdata) + jdata);
        }
        else if (typeof jdata === 'string')
        {
            jdata = get_char_codes(jdata);
        }

        try
        {
            edata = slowAES.encrypt(
                jdata,
                slowAES.modeOfOperation.CBC,
                key_arr,
                iv);
        }
        finally
        {
            if (!this.options.pad)
            {
                slowAES.padBytesIn = slowAES._padBytesIn_save;
            }
        }

        edata = String.fromCharCode.apply(String, edata);

        if (this.encoding)
        {
            edata = window.btoa(edata);
        }
    }
    catch (ex)
    {
        f.call(this, ex);
        return;
    }

    f.call(this, null, { iv: iv64, data: edata, ekey: ekey, version: SlowCrypt.get_version() });
};

SlowCrypt.prototype.decrypt = function (data, f)
{
    "use strict";

    var key_arr, ddata, jdata;

    try
    {
        if (!this.check_version(data, f))
        {
            return;
        }

        if (this.key.isPublic)
        {
            f.call(this, "can't decrypt using public key");
            return;
        }

        if (this.key.isPrivate)
        {
            key_arr = get_char_codes(this.key.decryptOAEP((this.encoding ? b64tohex : rstrtohex)(data.ekey)/*, rstr_sha256, 32*/));
        }
        else
        {
            key_arr = this.key.key || this.key;
        }

        if (!this.options.pad)
        {
            slowAES._unpadBytesOut_save = slowAES.unpadBytesOut;
            slowAES.unpadBytesOut = function (data)
            {
                return data;
            };
        }

        try
        {
            ddata = String.fromCharCode.apply(String, slowAES.decrypt(
                    get_char_codes(this.encoding ? window.atob(data.data) : data.data),
                    slowAES.modeOfOperation.CBC,
                    key_arr,
                    get_char_codes(this.encoding ? window.atob(data.iv) : data.iv)));
        }
        finally
        {
            if (!this.options.pad)
            {
                slowAES.unpadBytesOut = slowAES._unpadBytesOut_save;
            }
        }

        if (this.options.check)
        {
            jdata = ddata.substr(SHA256_SIZE);

            if (!const_time_equal(rstr_sha256(jdata), ddata.substr(0, SHA256_SIZE)))
            {
                f.call(this, 'digest mismatch');
                return;
            }
        }
        else
        {
            jdata = ddata;
        }

        jdata = this.parse(jdata);
    }
    catch (ex)
    {
        f.call(this, ex);
        return;
    }

    f.call(this, null, jdata);
};

SlowCrypt.prototype.sign = function (data, f)
{
    "use strict";

    var jdata, signature;
    
    try
    {
        if (this.key.isPublic)
        {
            f.call(this, "can't sign using public key");
            return;
        }

        jdata = this.stringify(data);

        if (typeof jdata !== 'string')
        {
            jdata = String.fromCharCode.apply(String, jdata);
        }

        if (this.key.isPrivate)
        {
            signature = (this.encoding ? hex2b64 : hextorstr)(this.key.signPSS(jdata, 'sha256'));
        }
        else
        {
            signature = rstr_hmac_sha256(String.fromCharCode.apply(
                            String, this.key.key || this.key), jdata);

            if (this.encoding)
            {
                signature = window.btoa(signature);
            }
        }

        if (this.encoding)
        {
            jdata = window.btoa(jdata);
        }
    }
    catch (ex)
    {
        f.call(this, ex);
        return;
    }

    f.call(this, null, { data: jdata, signature: signature, version: SlowCrypt.get_version() });
};

SlowCrypt.prototype.verify = function (data, f)
{
    "use strict";

    var match, ddata, jdata;

    try
    {
        if (!this.check_version(data, f))
        {
            return;
        }

        ddata = this.encoding ? window.atob(data.data) : data.data;

        if (this.key.isPrivate)
        {
            f.call(this, "can't verify using private key");
            return;
        }

        if (this.key.isPublic)
        {
            match = this.key.verifyPSS(ddata, (this.encoding ? b64tohex : rstrtohex)(data.signature), 'sha256');
        }
        else
        {
            match = const_time_equal(rstr_hmac_sha256(String.fromCharCode.apply(
                                         String, this.key.key || this.key), ddata),
                                     this.encoding ? window.atob(data.signature) : data.signature);
        }

        if (match)
        {
            jdata = this.parse(ddata);
        }
        else
        {
            f.call(this, 'digest mismatch');
            return;
        }
    }
    catch (ex)
    {
        f.call(this, ex);
        return;
    }

    f.call(this, null, jdata);
};

if (typeof exports === 'object')
{
    exports.Crypt = Crypt;
    exports.SlowCrypt = SlowCrypt;
}
