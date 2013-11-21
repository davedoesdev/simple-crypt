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
        Crypt.make(get_encrypt_key(), function (err, crypt)
        {
            if (err)
            {
                callback(err);
                return;
            }
                
            crypt.encrypt(json_vector, function (err, ev)
            {
                if (expect_encrypt_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);

                var decrypt_key = get_decrypt_key(this.key),
            
                decrypt = function (err, ths)
                {
                    if (err)
                    {
                        callback(err);
                        return;
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
                        Crypt.make(decrypt_key, function (err, decrypt)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }

                            decrypt.decrypt(ev, function (err, dv)
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
                        });
                    }], callback);
                };
                   
                if (decrypt_key === this.key)
                {
                    decrypt(null, this);
                }
                else
                {
                    Crypt.make(decrypt_key, decrypt);
                }
            });
        });
    });

    it('should maybe encrypt and decrypt JSON test vector', function (callback)
    {
        Crypt.make(get_encrypt_key(), function (err, crypt)
        {
            if (err)
            {
                callback(err);
                return;
            }
        
            crypt.maybe_encrypt(json_vector,
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

                Crypt.make(get_decrypt_key(this.key), function (err, decrypt)
                {
                    if (err)
                    {
                        callback(err);
                        return;
                    }
                
                    decrypt.maybe_decrypt(ev, function (err, dv)
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
        });
    });

    it('should maybe not encrypt and decrypt JSON test vector', function (callback)
    {
        Crypt.make(function (err, encrypt)
        {
            if (err)
            {
                callback(err);
                return;
            }
            
            encrypt.maybe_encrypt(false, json_vector, function (err, ev)
            {
                expr(expect(err, 'error').not.to.exist);
                expr(expect(ev.encrypted, 'encrypted').to.be.false);

                Crypt.make(function (err, decrypt)
                {
                    if (err)
                    {
                        callback(err);
                        return;
                    }
                    
                    decrypt.maybe_decrypt(ev, function (err, dv)
                    {
                        expr(expect(err, 'error').not.to.exist);
                        expect(dv, 'decrypted json test vector').to.eql(json_vector);
                        callback();
                    });
                });
            });
        });
    });

    it('should support key function', function (callback)
    {
        Crypt.make(function (err, encrypt)
        {
            if (err)
            {
                callback(err);
                return;
            }

            encrypt.options.custom = 'bar';
            
            encrypt.maybe_encrypt(json_vector, function (err, ev)
            {
                expr(expect(this).not.to.equal(encrypt));
                expr(expect(this.options.custom).to.equal('bar'));

                if (expect_encrypt_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expr(expect(ev.encrypted, 'encrypted').to.be.true);

                var decrypt_key = get_decrypt_key(this.key);

                Crypt.make(function (err, decrypt)
                {
                    if (err)
                    {
                        callback(err);
                        return;
                    }

                    decrypt.options.custom = 'bar2';
                    
                    decrypt.maybe_decrypt(ev, function (err, dv)
                    {
                        expr(expect(this).not.to.equal(decrypt));
                        expr(expect(this.options.custom).to.equal('bar2'));

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
                });
            }, function (cb)
            {
                cb(null, get_encrypt_key());
            });
        });
    });
}

exports.setup = setup;
