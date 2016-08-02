/*global Crypt: false,
         expect: false,
         describe: false,
         before: false,
         it: false */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

var crypto = require('crypto'),
    vector_helpers = require('./vector_helpers'),
    encrypt_decrypt = require('./encrypt_decrypt');

describe('encrypt_decrypt_symmetric', function ()
{
    var run_tasks, get_pbkdf_key;
    
    before(function (cb)
    {
        vector_helpers.read_aes_vectors(function (err, rt)
        {
            if (err)
            {
                cb(err);
                return;
            }

            run_tasks = rt;
            cb();
        });
    });

    it('should encrypt test vector plaintext and produce expected ciphertext', function (callback)
    {
        var slow = !!process.env.SLOW;

        run_tasks(function (task, cb)
        {
            Crypt.make(task.key, vector_helpers.vecopts, function (err, encrypt)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                encrypt.encrypt(task.plaintext, task.iv, function (err, v)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(Buffer.isBuffer(v.iv)).to.equal(!slow);
                    expect(Buffer.isBuffer(v.data)).to.equal(!slow);
                    expect(v.ekey).to.equal(undefined);
                    expect(v.data, 'expected ciphertext').to.eql(
                            slow ? task.ciphertext.toString('binary') :
                                   task.ciphertext);

                    cb();
                });
            });
        }, callback);
    });

    it('should decrypt test vector ciphertext and produce expected plaintext', function (callback)
    {
        var slow = !!process.env.SLOW;

        run_tasks(function (task, cb)
        {
            Crypt.make(task.key, vector_helpers.vecopts, function (err, decrypt)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                decrypt.decrypt(
                {
                    iv: slow ? task.iv.toString('binary') : task.iv,
                    data: slow ? task.ciphertext.toString('binary') : task.ciphertext,
                    version: Crypt.get_version()
                },
                function (err, v)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(Buffer.isBuffer(v)).to.equal(!slow);
                    expect(v, 'expected plaintext').to.eql(
                            slow ? task.plaintext.toString('binary') :
                                   task.plaintext);

                    cb();
                });
            });
        }, callback);
    });

    it('pbkdf2 should call progress function', function (done)
    {
        var p;

        Crypt.make(
        {
            password: 'hello',
            iterations: 10000,
            progress: function (n)
            {
                p = n;
            }
        }, function (err)
        {
            expect(err).to.equal(null);
            expect(p).to.equal(100);
            done();
        });
    });

    it('should support string initialisation vectors', function (done)
    {
        Crypt.make('symmetric key   ', function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.encrypt('hello', 'initzn vector   ', function (err, edata)
            {
                expect(err).to.equal(null);
                expect(edata.iv).to.equal(new Buffer('initzn vector   ', 'binary').toString('base64'));
                crypt.decrypt(edata, function (err, ddata)
                {
                    expect(err).to.equal(null);
                    expect(ddata).to.equal('hello');

                    Crypt.make('symmetric key   ',
                    {
                        base64: false
                    }, function (err, crypt)
                    {
                        expect(err).to.equal(null);
                        crypt.encrypt('hello', 'initzn vector   ', function (err, edata)
                        {
                            expect(err).to.equal(null);
                            expect(edata.iv).to.eql(process.env.SLOW ?
                                    'initzn vector   ' :
                                    new Buffer('initzn vector   ', 'binary'));
                            crypt.decrypt(edata, function (err, ddata)
                            {
                                expect(err).to.equal(null);
                                expect(ddata).to.equal('hello');
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    encrypt_decrypt.setup(function ()
    {
        return crypto.randomBytes(Crypt.get_key_size());
    }, function (encrypt_key)
    {
        return encrypt_key;
    });

    encrypt_decrypt.setup(function ()
    {
        return {
            password: 'some random password',
            iterations: process.env.SLOW ? 1500 : 150000
        };
    }, function (encrypt_key)
    {
        return encrypt_key;
    });

    get_pbkdf_key = function ()
    {
        return {
            password: 'some random password',
            salt: 'some salt value',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    };

    encrypt_decrypt.setup(get_pbkdf_key, get_pbkdf_key);

    encrypt_decrypt.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function (encrypt_key)
    {
        return {
            password: 'pass1',
            salt: encrypt_key.salt,
            iterations: process.env.SLOW ? 1000 : 100000
        };
    });

    encrypt_decrypt.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, false, true);

    encrypt_decrypt.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function (encrypt_key)
    {
        return {
            password: 'pass1',
            salt: encrypt_key.salt,
            iterations: process.env.SLOW ? 1001 : 100001
        };
    }, false, true);

    encrypt_decrypt.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function ()
    {
        return {
            password: 'pass1',
            salt: 'random',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, false, true);
});

