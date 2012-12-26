/*global require,
         exports,
         Buffer,
         Uint8Array,
         slowAES,
         rstr2hex,
         rstr_sha256,
         escape,
         unescape */

// Simple crypto using AES and a hash to check integrity.
// Uses crypto under node.js and slowaes/jshash in the browser.

// Note: Keep an eye on http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-00

var Crypt;

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

        var iv = crypto.randomBytes(16),
            cipher = crypto.createCipheriv('AES-128-CBC', this.key, iv),
            jdata = JSON.stringify(data),
            edata = cipher.update(crypto.createHash('sha256')
                        .update(jdata, 'utf8')
                        .digest('hex'), 'utf8', 'base64');

        edata += cipher.update(jdata, 'utf8', 'base64');

        edata += cipher.final('base64');

        f(null, { iv: iv.toString('base64'), data: edata });
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

        jdata = ddata.substr(64);

        if (crypto.createHash('sha256').update(jdata, 'utf8').digest('hex') ===
            ddata.substr(0, 64))
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
}
else
{
    var SHA256_SIZE = 32, AES_BLOCK_SIZE = 16,

    get_char_codes = function(s)
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
        this.key = (typeof key === "string") ? get_char_codes(key) : key;
    };

    Crypt.prototype.encrypt = function (data, f)
    {
        "use strict";

        var iv = new Uint8Array(AES_BLOCK_SIZE),
            // http://ecmanaut.blogspot.co.uk/2006/07/encoding-decoding-utf8-in-javascript.html
            jdata = unescape(encodeURIComponent(JSON.stringify(data))),
            edata;

        window.crypto.getRandomValues(iv);

        edata = slowAES.encrypt(
            get_char_codes(rstr2hex(rstr_sha256(jdata)) + jdata),
            slowAES.modeOfOperation.CBC,
            this.key,
            iv);

        f(null, { iv: window.btoa(String.fromCharCode.apply(String, Array.prototype.slice.call(iv))),
                  data: window.btoa(String.fromCharCode.apply(String, edata)) });
    };

    Crypt.prototype.decrypt = function (data, f)
    {
        "use strict";

        var iv = get_char_codes(window.atob(data.iv)),
            edata = get_char_codes(window.atob(data.data)),
            ddata = String.fromCharCode.apply(String, slowAES.decrypt(
                edata,
                slowAES.modeOfOperation.CBC,
                this.key,
                iv)),
            digest = hex_decode(ddata.substr(0, SHA256_SIZE * 2));

        ddata = ddata.substr(SHA256_SIZE * 2);

        if (rstr_sha256(ddata) === digest)
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
}

Crypt.prototype.maybe_encrypt = function (encrypt, data, f)
{
    "use strict";

    if (f === undefined)
    {
        f = data;
        data = encrypt;
        encrypt = this.key && this.key.length;
    }

    if (encrypt)
    {
        this.encrypt(data, function (err, edata)
        {
            f(err, { encrypted: true, data: edata });
        });
    }
    else
    {
        f(null, { encrypted: false, data: data });
    }
};

Crypt.prototype.maybe_decrypt = function (data, f, get_key)
{
    "use strict";

    if (data.encrypted)
    {
        if (get_key)
        {
            get_key(function (err, key)
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

if (typeof exports === 'object')
{
    exports.Crypt = Crypt;
}
