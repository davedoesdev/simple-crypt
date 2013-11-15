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
        run_tasks(function (task, cb)
        {
            new Crypt(task.key, vector_helpers.vecopts).sign(task.msg,
            function (err, v)
            {
                expr(expect(err, 'error').not.to.exist);
                expect(v.signature, 'expected mac').to.equal(task.mac.toString('base64'));

                cb();
            });
        }, callback);
    });

    it('should verify test vector mac', function (callback)
    {
        run_tasks(function (task, cb)
        {
            new Crypt(task.key, vector_helpers.vecopts).verify(
            {
                data: task.msg.toString('base64'),
                signature: task.mac.toString('base64'),
                version: Crypt.get_version()
            },
            function (err, v)
            {
                expr(expect(err, 'error').not.to.exist);
                expect(v.toString('base64'), 'expected msg').to.equal(task.msg.toString('base64'));

                cb();
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

