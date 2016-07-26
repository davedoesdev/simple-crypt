/*global expect: false,
         Crypt: false,
         it: false */
/*jslint node: true */
"use strict";

var crypto = require('crypto'),
    PassThrough = require('stream').PassThrough;

exports.setup = function (signing_key, encryption_key, decryption_key, verifying_key)
{
    it('should encrypt to a stream and decrypt from a stream', function (cb)
    {
        var buf = crypto.randomBytes(100 * 1024),
            buf2 = crypto.randomBytes(1),
            buf3 = crypto.randomBytes(100),
            pthru = new PassThrough();

        Crypt.encrypt_stream(encryption_key, pthru, function (err, enc_stream)
        {
            if (err) { return cb(err); }
            Crypt.decrypt_stream(decryption_key, enc_stream, function (err, dec_stream)
            {
                if (err) { return cb(err); }

                var bufs = [];

                dec_stream.on('readable', function ()
                {
                    while (true)
                    {
                        var buf = this.read();
                        if (!buf)
                        {
                            break;
                        }
                        bufs.push(buf);
                    }
                });

                dec_stream.on('end', function ()
                {
                    expect(Buffer.concat(bufs)).to.eql(Buffer.concat([buf, buf2, buf3]));
                    cb();
                });
            });
        });

        pthru.write(buf);
        pthru.write(buf2);
        pthru.end(buf3);
    });

    it('should sign to a stream and verify from a stream', function (cb)
    {
        var buf = crypto.randomBytes(100 * 1024),
            buf2 = crypto.randomBytes(1),
            buf3 = crypto.randomBytes(100),
            pthru = new PassThrough();

        Crypt.sign_stream(signing_key, pthru, function (err, sign_stream)
        {
            if (err) { return cb(err); }
            Crypt.verify_stream(verifying_key, sign_stream, function (err, verify_stream)
            {
                if (err) { return cb(err); }

                var bufs = [];

                verify_stream.on('readable', function ()
                {
                    while (true)
                    {
                        var buf = this.read();
                        if (!buf)
                        {
                            break;
                        }
                        bufs.push(buf);
                    }
                });

                verify_stream.on('end', function ()
                {
                    expect(Buffer.concat(bufs)).to.eql(Buffer.concat([buf, buf2, buf3]));
                    cb();
                });
            });
        });

        pthru.write(buf);
        pthru.write(buf2);
        pthru.end(buf3);
    });

    it('should sign then encrypt then sign to a stream and verify then decrypt then verify from a stream', function (cb)
    {
        var buf = crypto.randomBytes(100 * 1024),
            buf2 = crypto.randomBytes(1),
            buf3 = crypto.randomBytes(100),
            pthru = new PassThrough();

        Crypt.sign_encrypt_sign_stream(signing_key, encryption_key, pthru, function (err, ses_stream)
        {
            if (err) { return cb(err); }
            Crypt.verify_decrypt_verify_stream(decryption_key, verifying_key, ses_stream, function (err, vdv_stream)
            {
                if (err) { return cb(err); }

                var bufs = [];

                vdv_stream.on('readable', function ()
                {
                    while (true)
                    {
                        var buf = this.read();
                        if (!buf)
                        {
                            break;
                        }
                        bufs.push(buf);
                    }
                });

                vdv_stream.on('end', function ()
                {
                    expect(Buffer.concat(bufs)).to.eql(Buffer.concat([buf, buf2, buf3]));
                    cb();
                });
            });
        });

        pthru.write(buf);
        pthru.write(buf2);
        pthru.end(buf3);
    });
};
