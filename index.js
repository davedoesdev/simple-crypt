/*global require,
         exports,
         Buffer,
         Uint8Array,
         slowAES,
         rstr2hex,
         rstr_sha256,
         rstr_hmac_sha256,
         escape,
         unescape,
         RSAKey,
         hex2b64,
         b64tohex */

// Simple symmetric and asymmetric crypto.
// Note: Keep an eye on http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-02

var version = 1;

var SHA256_SIZE = 32,
    AES_BLOCK_SIZE = 16,
    AES_128_KEY_SIZE = 16,

Crypt = function (key)
{
    "use strict";
    this.key = Crypt.parse_key(key);
};

Crypt.check_version = function (data, f)
{
    "use strict";

    if (data.version > version)
    {
        f('unsupported version');
        return false;
    }
    
    return true;
};

if (typeof require === 'function')
{
    var crypto = require('crypto'),
        ursa = require('ursa');

    Crypt.parse_key = function (key)
    {
        "use strict";

        if ((typeof key === 'string') && (key.indexOf('-----BEGIN') === 0))
        {
            if (key.indexOf('PUBLIC KEY') > 0)
            {
                key = ursa.createPublicKey(key, 'utf8');
            }
            else if (key.indexOf('PRIVATE KEY') > 0)
            {
                key = ursa.createPrivateKey(key, '', 'utf8');
            }
        }

        return key;
    };

    Crypt.prototype.encrypt = function (data, f)
    {
        "use strict";

        var key, ekey, iv, iv64, cipher, jdata, edata;

        try
        {
            if (this.key.encrypt)
            {
                key = crypto.randomBytes(AES_128_KEY_SIZE);
                ekey = this.key.encrypt(key, 'binary', 'base64');
            }
            else
            {
                key = this.key;
            }

            iv = crypto.randomBytes(AES_BLOCK_SIZE);
            iv64 = iv.toString('base64');
            cipher = crypto.createCipheriv('AES-128-CBC', key, iv);
            jdata = new Buffer(JSON.stringify(data), 'utf8');
            edata = cipher.update(crypto.createHash('sha256')
                            //.update(iv64, 'utf8')
                            .update(jdata)
                            .digest('hex'), 'utf8', 'base64');

            edata += cipher.update(jdata, 'utf8', 'base64');

            edata += cipher.final('base64');
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, { iv: iv64, data: edata, ekey: ekey, version: version });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var key, decipher, ddata, jdata;

        try
        {
            if (!Crypt.check_version(data, f))
            {
                return;
            }

            if (this.key.decrypt)
            {
                key = this.key.decrypt(data.ekey, 'base64', 'binary');
            }
            else
            {
                key = this.key;
            }

            decipher = crypto.createDecipheriv(
                    'AES-128-CBC',
                    key,
                    new Buffer(data.iv, 'base64'));
            ddata = decipher.update(data.data, 'base64', 'utf8');

            ddata += decipher.final('utf8');

            jdata = ddata.substr(SHA256_SIZE * 2);

            if (crypto.createHash('sha256')
                    //.update(data.iv)
                    .update(jdata, 'utf8')
                    .digest('hex') === ddata.substr(0, SHA256_SIZE * 2))
            {
                jdata = JSON.parse(jdata);
            }
            else
            {
                f('digest mismatch');
                return;
            }
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, jdata);
    };

    Crypt.prototype.sign = function (data, f)
    {
        "use strict";

        var jdata, signature;

        try
        {
            jdata = JSON.stringify(data);

            if (this.key.hashAndSign)
            {
                signature = this.key.hashAndSign('sha256', jdata, 'utf8', 'base64', ursa.RSA_PKCS1_PSS_PADDING);
            }
            else
            {
                signature = crypto.createHmac('sha256', this.key)
                        .update(new Buffer(jdata, 'utf8'))
                        .digest('base64');
            }
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, { data: jdata, signature: signature, version: version });
    };

    Crypt.prototype.verify = function (data, f)
    {
        "use strict";

        var match, jdata;

        try
        {
            if (!Crypt.check_version(data, f))
            {
                return;
            }

            if (this.key.hashAndVerify)
            {
                match = this.key.hashAndVerify(
                            'sha256',
                            new Buffer(data.data, 'utf8').toString('base64'),
                            data.signature,
                            'base64',
                            ursa.RSA_PKCS1_PSS_PADDING);
            }
            else
            {
                match = crypto.createHmac('sha256', this.key)
                        .update(new Buffer(data.data, 'utf8'))
                        .digest('base64') === data.signature;
            }

            if (match)
            {
                jdata = JSON.parse(data.data);
            }
            else
            {
                f('digest mismatch');
                return;
            }
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, jdata);
    };
}
else
{
    var get_char_codes = function(s)
    {
        "use strict";

        var r = [], i;

        for (i = 0; i < s.length; i += 1)
        {
            r.push(s.charCodeAt(i));
        }

        return r;
    },

    hex_decode = function (s)
    {
        "use strict";

        var r = "", i;

        for (i = 0; i <= s.length - 2; i += 2)
        {
            r += String.fromCharCode(parseInt(s.substr(i, 2), 16));
        }

        return r;
    };
    
    Crypt.parse_key = function (key)
    {
        "use strict";

        var r = key;

        if ((typeof key === 'string') && (key.indexOf('-----BEGIN') === 0))
        {
            if (key.indexOf('PUBLIC KEY') > 0)
            {
                r = new RSAKey();
                r.readPublicKeyFromPEMString(key);
            }
            else if (key.indexOf('PRIVATE KEY') > 0)
            {
                r = new RSAKey();
                r.readPrivateKeyFromPEMString(key);
            }
            else if (key)
            {
                r = get_char_codes(key);
            }
        }

        return r;
    };

    Crypt.prototype.encrypt = function (data, f)
    {
        "use strict";

        var key_arr, ekey, iv, iv64, jdata, edata;

        try
        {
            if (this.key.encryptOAEP)
            {
                key_arr = new Uint8Array(AES_128_KEY_SIZE);
                window.crypto.getRandomValues(key_arr);
                ekey = hex2b64(this.key.encryptOAEP(String.fromCharCode.apply(String, Array.prototype.slice.call(key_arr))));
            }
            else if (this.key)
            {
                key_arr = this.key;
            }
            else
            {
                key_arr = [];
            }

            iv = new Uint8Array(AES_BLOCK_SIZE);
            // http://ecmanaut.blogspot.co.uk/2006/07/encoding-decoding-utf8-in-javascript.html
            jdata = unescape(encodeURIComponent(JSON.stringify(data)));

            window.crypto.getRandomValues(iv);
            iv64 = window.btoa(String.fromCharCode.apply(String, Array.prototype.slice.call(iv)));

            edata = slowAES.encrypt(
                get_char_codes(rstr2hex(rstr_sha256(/*iv64 + */jdata)) + jdata),
                slowAES.modeOfOperation.CBC,
                key_arr,
                iv);

            edata = window.btoa(String.fromCharCode.apply(String, edata));
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, { iv: iv64, data: edata, ekey: ekey, version: version });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var key_arr, iv, edata, ddata, digest;

        try
        {
            if (!Crypt.check_version(data, f))
            {
                return;
            }

            if (this.key.decryptOAEP)
            {
                key_arr = get_char_codes(this.key.decryptOAEP(b64tohex(data.ekey)));
            }
            else if (this.key)
            {
                key_arr = this.key;
            }
            else
            {
                key_arr = [];
            }

            iv = get_char_codes(window.atob(data.iv));
            edata = get_char_codes(window.atob(data.data));
            ddata = String.fromCharCode.apply(String, slowAES.decrypt(
                    edata,
                    slowAES.modeOfOperation.CBC,
                    key_arr,
                    iv));
            digest = hex_decode(ddata.substr(0, SHA256_SIZE * 2));

            ddata = ddata.substr(SHA256_SIZE * 2);

            if (rstr_sha256(/*data.iv + */ddata) === digest)
            {
                ddata = JSON.parse(decodeURIComponent(escape(ddata)));
            }
            else
            {
                f('digest mismatch');
                return;
            }
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, ddata);
    };

    Crypt.prototype.sign = function (data, f)
    {
        "use strict";

        var jdata = unescape(encodeURIComponent(JSON.stringify(data))),
            signature;
            
        if (this.key.signPSS)
        {
            signature = hex2b64(this.key.signPSS(jdata, 'sha256'));
        }
        else
        {
            signature = window.btoa(rstr_hmac_sha256(String.fromCharCode.apply(
                            String, this.key || []), jdata));
        }

        f(null, { data: jdata, signature: signature, version: version });
    };

    Crypt.prototype.verify = function (data, f)
    {
        "use strict";

        var match, jdata;

        try
        {
            if (!Crypt.check_version(data, f))
            {
                return;
            }

            if (this.key.verifyPSS)
            {
                match = this.key.verifyPSS(data.data, b64tohex(data.signature), 'sha256');
            }
            else
            {
                match = window.btoa(rstr_hmac_sha256(String.fromCharCode.apply(
                            String, this.key || []), data.data)) ===
                        data.signature;
            }

            if (match)
            {
                jdata = JSON.parse(decodeURIComponent(escape(data.data)));
            }
            else
            {
                f('digest mismatch');
                return;
            }
        }
        catch (ex)
        {
            f(ex);
            return;
        }

        f(null, jdata);
    };
}

Crypt.prototype.key_size = AES_128_KEY_SIZE;

Crypt.prototype.maybe_encrypt = function (arg_encrypt,
                                          arg_data,
                                          arg_f,
                                          arg_get_key)
{
    "use strict";

    var encrypt, data, f, get_key, get_key_data,

    encrypted = function (err, edata, key_data)
    {
        if (err)
        {
            f(err);
        }
        else
        {
            f(null, { encrypted: true, data: edata, key_data: key_data });
        }
    },
    
    not_encrypted = function ()
    {
        f(null, { encrypted: false, data: data });
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
            get_key_data.push(function (err, key, key_data)
            {
                if (err)
                {
                    f(err);
                }
                else if (key)
                {
                    new Crypt(key).encrypt(data, function (err, data)
                    {
                        encrypted(err, data, key_data);
                    });
                }
                else
                {
                    not_encrypted();
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
        not_encrypted();
    }
};

Crypt.prototype.maybe_decrypt = function (data, f, get_key)
{
    "use strict";

    if (data.encrypted)
    {
        if (get_key !== undefined)
        {
            var get_key_data = Array.prototype.slice.call(arguments, 3);

            get_key_data.push(function (err, key)
            {
                if (err)
                {
                    f(err);
                }
                else
                {
                    new Crypt(key).decrypt(data.data, f);
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
        f(null, data.data);
    }
};

Crypt.prototype.maybe_sign = function (arg_sign, arg_data, arg_f, arg_get_key)
{
    "use strict";

    var sign, data, f, get_key, get_key_data,

    signed = function (err, sdata, key_data)
    {
        if (err)
        {
            f(err);
        }
        else
        {
            f(null, { signed: true, data: sdata, key_data: key_data });
        }
    },

    not_signed = function ()
    {
        f(null, { signed: false, data: data });
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
                    f(err);
                }
                else if (key)
                {
                    new Crypt(key).sign(data, function (err, data)
                    {
                        signed(err, data, key_data);
                    });
                }
                else
                {
                    not_signed();
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
        not_signed();
    }
};

Crypt.prototype.maybe_verify = function (data, f, get_key)
{
    "use strict";

    if (data.signed)
    {
        if (get_key !== undefined)
        {
            var get_key_data = Array.prototype.slice.call(arguments, 3);

            get_key_data.push(function (err, key)
            {
                if (err)
                {
                    f(err);
                }
                else
                {
                    new Crypt(key).verify(data.data, f);
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
        f(null, data.data);
    }
};

if (typeof exports === 'object')
{
    exports.Crypt = Crypt;
}
