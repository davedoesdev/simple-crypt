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
                    expect(v.data, 'expected ciphertext').to.equal(task.ciphertext.toString('base64'));

                    cb();
                });
            });
        }, callback);
    });

    it('should decrypt test vector ciphertext and produce expected plaintext', function (callback)
    {
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
                    iv: task.iv.toString('base64'),
                    data: task.ciphertext.toString('base64'),
                    version: Crypt.get_version()
                },
                function (err, v)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(v.toString('base64'), 'expected plaintext').to.equal(task.plaintext.toString('base64'));

                    cb();
                });
            });
        }, callback);
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

