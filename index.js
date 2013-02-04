/*global require,
         exports,
         Buffer,
         Uint8Array,
         slowAES,
         rstr2hex,
         rstr_sha256,
         rstr_hmac_sha256,
         escape,
         unescape */

// Simple crypto using AES and a hash to check integrity.
// Uses crypto under node.js and slowaes/jshash in the browser.

// Note: Keep an eye on http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-00

var Crypt,
    SHA256_SIZE = 32,
    AES_BLOCK_SIZE = 16,
    AES_128_KEY_SIZE = 16;

if (typeof require === 'function')
{
    var crypto = require('crypto'),

    Crypt = function (key)
    {
        "use strict";
        this.key = key;
    };

    Crypt.prototype.encrypt = function (data, f)
    {
        "use strict";

        var iv = crypto.randomBytes(AES_BLOCK_SIZE),
            iv64 = iv.toString('base64'),
            cipher = crypto.createCipheriv('AES-128-CBC', this.key, iv),
            jdata = new Buffer(JSON.stringify(data), 'utf-8'),
            edata = cipher.update(crypto.createHash('sha256')
                        //.update(iv64, 'utf8')
                        .update(jdata)
                        .digest('hex'), 'utf8', 'base64');

        edata += cipher.update(jdata, 'utf8', 'base64');

        edata += cipher.final('base64');

        f(null, { iv: iv64, data: edata });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var decipher = crypto.createDecipheriv(
                'AES-128-CBC',
                this.key,
                new Buffer(data.iv, 'base64')),
            ddata = decipher.update(data.data, 'base64'),
            jdata;

        ddata += decipher.final('utf8');

        jdata = ddata.substr(SHA256_SIZE * 2);

        if (crypto.createHash('sha256')
                //.update(data.iv)
                .update(jdata, 'utf8')
                .digest('hex') === ddata.substr(0, SHA256_SIZE * 2))
        {
            try
            {
                jdata = JSON.parse(jdata);
            }
            catch (ex)
            {
                f(ex);
                return;
            }

            f(null, jdata);
        }
        else
        {
            f("digest mismatch");
        }
    };

    Crypt.prototype.sign = function (data, f)
    {
        "use strict";

        var jdata = JSON.stringify(data),
            signature = crypto.createHmac('sha256', this.key)
                    .update(new Buffer(jdata, 'utf-8'))
                    .digest('base64');

        f(null, { data: jdata, signature: signature });
    };

    Crypt.prototype.verify = function (data, f)
    {
        "use strict";

        if (crypto.createHmac('sha256', this.key)
                .update(new Buffer(data.data, 'utf-8'))
                .digest('base64') === data.signature)
        {
            f(null, JSON.parse(data.data));
        }
        else
        {
            f('digest mismatch');
        }
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
    },
    
    Crypt = function (key)
    {
        "use strict";
        this.key = key;
        this.key_arr = (typeof key === "string") ? get_char_codes(key) : key;
    };

    Crypt.prototype.encrypt = function (data, f)
    {
        "use strict";

        var iv = new Uint8Array(AES_BLOCK_SIZE),
            iv64,
            // http://ecmanaut.blogspot.co.uk/2006/07/encoding-decoding-utf8-in-javascript.html
            jdata = unescape(encodeURIComponent(JSON.stringify(data))),
            edata;

        window.crypto.getRandomValues(iv);
        iv64 = window.btoa(String.fromCharCode.apply(String, Array.prototype.slice.call(iv)));

        edata = slowAES.encrypt(
            get_char_codes(rstr2hex(rstr_sha256(/*iv64 + */jdata)) + jdata),
            slowAES.modeOfOperation.CBC,
            this.key_arr,
            iv);

        f(null, { iv: iv64, data: window.btoa(String.fromCharCode.apply(String, edata)) });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var iv = get_char_codes(window.atob(data.iv)),
            edata = get_char_codes(window.atob(data.data)),
            ddata = String.fromCharCode.apply(String, slowAES.decrypt(
                edata,
                slowAES.modeOfOperation.CBC,
                this.key_arr,
                iv)),
            digest = hex_decode(ddata.substr(0, SHA256_SIZE * 2));

        ddata = ddata.substr(SHA256_SIZE * 2);

        if (rstr_sha256(/*data.iv + */ddata) === digest)
        {
            try
            {
                ddata = JSON.parse(decodeURIComponent(escape(ddata)));
            }
            catch (ex)
            {
                f(ex);
                return;
            }

            f(null, ddata);
        }
        else
        {
            f("digest mismatch");
        }
    };

    Crypt.prototype.sign = function (data, f)
    {
        "use strict";

        var jdata = unescape(encodeURIComponent(JSON.stringify(data))),
            signature = window.btoa(rstr_hmac_sha256(this.key, jdata));

        f(null, { data: jdata, signature: signature });
    };

    Crypt.prototype.verify = function (data, f)
    {
        "use strict";

        if (window.btoa(rstr_hmac_sha256(this.key, data.data)) === data.signature)
        {
            f(null, JSON.parse(decodeURIComponent(escape(data.data))));
        }
        else
        {
            f('digest mismatch');
        }
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
        encrypt = (get_key !== undefined) || (this.key && this.key.length);
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
                else if (key && key.length)
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
        sign = (get_key !== undefined) || (this.key && this.key.length);
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
                else if (key && key.length)
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
