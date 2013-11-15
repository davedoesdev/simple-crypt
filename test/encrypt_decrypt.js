/*global expect: false,
         Crypt: false,
         json_vector: false,
         it: false */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

var async = require('async');

function setup(get_encrypt_key, get_decrypt_key, expect_encrypt_error, expect_decrypt_error)
{
    expect_decrypt_error = expect_decrypt_error || expect_encrypt_error;

    it('should encrypt and decrypt JSON test vector', function (callback)
    {
        new Crypt(get_encrypt_key()).encrypt(json_vector,
        function (err, ev)
        {
            if (expect_encrypt_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);

            var decrypt_key = get_decrypt_key(this.key), ths;

            if (decrypt_key === this.key)
            {
                ths = this;
            }
            else
            {
                ths = new Crypt(decrypt_key);
            }

            async.parallel([
    
            function (cb)
            {
                ths.decrypt(ev, function (err, dv)
                {
                    if (expect_decrypt_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);
                    expect(dv, 'decrypted json test vector').to.eql(json_vector);

                    cb();
                });
            },
            
            function (cb)
            {
                new Crypt(decrypt_key).decrypt(ev,
                function (err, dv)
                {
                    if (expect_decrypt_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);
                    expect(dv, 'decrypted json test vector').to.eql(json_vector);

                    cb();
                });
            }], callback);
        });
    });

    it('should maybe encrypt and decrypt JSON test vector', function (callback)
    {
        new Crypt(get_encrypt_key()).maybe_encrypt(json_vector,
        function (err, ev)
        {
            if (expect_encrypt_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);
            expr(expect(ev.encrypted, 'encrypted').to.be.true);

            new Crypt(get_decrypt_key(this.key)).maybe_decrypt(ev,
            function (err, dv)
            {
                if (expect_decrypt_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                callback();
            });
        });
    });

    it('should maybe not encrypt and decrypt JSON test vector', function (callback)
    {
        new Crypt().maybe_encrypt(false, json_vector, function (err, ev)
        {
            expr(expect(err, 'error').not.to.exist);
            expr(expect(ev.encrypted, 'encrypted').to.be.false);

            new Crypt().maybe_decrypt(ev, function (err, dv)
            {
                expr(expect(err, 'error').not.to.exist);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                callback();
            });
        });
    });

    it('should support key function', function (callback)
    {
        new Crypt().maybe_encrypt(json_vector,
        function (err, ev)
        {
            if (expect_encrypt_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);
            expr(expect(ev.encrypted, 'encrypted').to.be.true);

            var decrypt_key = get_decrypt_key(this.key);

            new Crypt().maybe_decrypt(ev, function (err, dv)
            {
                if (expect_decrypt_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                callback();
            }, function (cb)
            {
                cb(null, decrypt_key);
            });
        }, function (cb)
        {
            cb(null, get_encrypt_key());
        });
    });
}

exports.setup = setup;
