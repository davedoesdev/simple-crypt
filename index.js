/*jslint node: true */

// Simple wrapper around node crypto for encrypt/decrypt.

// Note: Keep an eye on http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-00

"use strict";

var crypto = require('crypto');

function Crypt(key)
{
    this.key = key;
}

Crypt.prototype.encrypt = function (data, f)
{
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
        f(null, JSON.parse(jdata));
    }
    else
    {
        f("digest mismatch");
    }
};

exports.Crypt = Crypt;
