/*global describe: false,
         expect: false,
         Crypt: false,
         it: false,
         before: false */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

var crypto = require('crypto'),
    vector_helpers = require('./vector_helpers'),
    sign_verify = require('./sign_verify');

describe('sign_verify_symmetric', function ()
{
    var run_tasks, get_pbkdf_key;
    
    before(function (cb)
    {
        vector_helpers.read_hmac_vectors(function (err, rt)
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

    it('should sign test vector message and produce expected mac', function (callback)
    {
        var slow = !!process.env.SLOW;

        run_tasks(function (task, cb)
        {
            Crypt.make(task.key, vector_helpers.vecopts, function (err, sign)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                sign.sign(task.msg, function (err, v)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(Buffer.isBuffer(v.data)).to.equal(!slow);
                    expect(Buffer.isBuffer(v.signature)).to.equal(!slow);
                    expect(v.signature, 'expected mac').to.eql(
                            slow ? task.mac.toString('binary') : task.mac);

                    cb();
                });
            });
        }, callback);
    });

    it('should verify test vector mac', function (callback)
    {
        var slow = !!process.env.SLOW;

        run_tasks(function (task, cb)
        {
            Crypt.make(task.key, vector_helpers.vecopts, function (err, verify)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                verify.verify(
                {
                    data: slow ? task.msg.toString('binary') : task.msg,
                    signature: slow ? task.mac.toString('binary') : task.mac,
                    version: Crypt.get_version()
                },
                function (err, v)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(Buffer.isBuffer(v)).to.equal(!slow);
                    expect(v, 'expected msg').to.eql(
                            slow ? task.msg.toString('binary') : task.msg);

                    cb();
                });
            });
        }, callback);
    });

    sign_verify.setup(function ()
    {
        return {
            password: 'hello world',
            iterations: process.env.SLOW ? 1500 : 150000
        };
    }, function (signing_key)
    {
        return signing_key;
    });

    get_pbkdf_key = function ()
    {
        return {
            password: 'PassW0rd',
            salt: 'context',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    };

    sign_verify.setup(get_pbkdf_key, get_pbkdf_key);

    sign_verify.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function (signing_key)
    {
        return {
            password: 'pass1',
            salt: signing_key.salt,
            iterations: process.env.SLOW ? 1000 : 100000
        };
    });

    sign_verify.setup(function ()
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

    sign_verify.setup(function ()
    {
        return {
            password: 'pass1',
            iterations: process.env.SLOW ? 1000 : 100000
        };
    }, function (signing_key)
    {
        return {
            password: 'pass1',
            salt: signing_key.salt,
            iterations: process.env.SLOW ? 1001 : 100001
        };
    }, false, true);

    sign_verify.setup(function ()
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

var i;

function make_random_tester(i)
{
    return function ()
    {
        sign_verify.setup(function ()
        {
            return crypto.randomBytes(i);
        }, function (signing_key)
        {
            return signing_key;
        });
    };
}

for (i = 0; i < 10000; i += 1)
{
    describe('sign_verify_symmetric_' + i, make_random_tester(i));
}

