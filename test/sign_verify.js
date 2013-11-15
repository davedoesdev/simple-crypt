/*global expect: true,
         Crypt: true,
         json_vector: true,
         it: true */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

var async = require('async');

function setup(get_signing_key, get_verifying_key, expect_sign_error, expect_verify_error)
{
    expect_verify_error = expect_verify_error || expect_sign_error;

    it('should sign and verify JSON test vector', function (callback)
    {
        new Crypt(get_signing_key()).sign(json_vector,
        function (err, sv)
        {
            if (expect_sign_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);

            var verifying_key = get_verifying_key(this.get_key()), ths;

            if (verifying_key === this.get_key())
            {
                ths = this;
            }
            else
            {
                ths = new Crypt(verifying_key);
            }

            async.parallel([
    
            function (cb)
            {
                ths.verify(sv, function (err, vv)
                {
                    if (expect_verify_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);
                    expect(vv, 'verified json test vector').to.eql(json_vector);

                    cb();
                });
            },
            
            function (cb)
            {
                new Crypt(verifying_key).verify(sv,
                function (err, vv)
                {
                    if (expect_verify_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);
                    expect(vv, 'verified json test vector').to.eql(json_vector);

                    cb();
                });
            }], callback);
        });
    });

    it('should maybe sign and verify JSON test vector', function (callback)
    {
        new Crypt(get_signing_key()).maybe_sign(json_vector,
        function (err, sv)
        {
            if (expect_sign_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);
            expr(expect(sv.signed, 'signed').to.be.true);

            new Crypt(get_verifying_key(this.get_key())).maybe_verify(sv,
            function (err, vv)
            {
                if (expect_verify_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expect(vv, 'verified json test vector').to.eql(json_vector);
                callback();
            });
        });
    });

    it('should maybe not sign and verify JSON test vector', function (callback)
    {
        new Crypt().maybe_sign(false, json_vector, function (err, sv)
        {
            expr(expect(err, 'error').not.to.exist);
            expr(expect(sv.signed, 'signed').to.be.false);

            new Crypt().maybe_verify(sv, function (err, vv)
            {
                expr(expect(err, 'error').not.to.exist);
                expect(vv, 'verified json test vector').to.eql(json_vector);
                callback();
            });
        });
    });

    it('should support key function', function (callback)
    {
        new Crypt().maybe_sign(json_vector,
        function (err, sv)
        {
            if (expect_sign_error)
            {
                expr(expect(err, 'expected error').to.exist);
                callback();
                return;
            }

            expr(expect(err, 'error').not.to.exist);
            expr(expect(sv.signed, 'signed').to.be.true);

            var verifying_key = get_verifying_key(this.get_key());

            new Crypt().maybe_verify(sv, function (err, vv)
            {
                if (expect_verify_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expect(vv, 'verified json test vector').to.eql(json_vector);
                callback();
            }, function (cb)
            {
                cb(null, verifying_key);
            });
        }, function (cb)
        {
            cb(null, get_signing_key());
        });
    });
}

exports.setup = setup;
