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
        Crypt.make(get_signing_key(), function (err, sign)
        {
            if (err)
            {
                callback(err);
                return;
            }
            
            sign.sign(json_vector, function (err, sv)
            {
                if (expect_sign_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);

                var verifying_key = get_verifying_key(this.get_key()),

                verify = function (err, ths)
                {
                    if (err)
                    {
                        callback(err);
                        return;
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
                        Crypt.make(verifying_key, function (err, verify)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            verify.verify(sv, function (err, vv)
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
                        });
                    }], callback);
                };

                if (verifying_key === this.get_key())
                {
                    verify(null, this);
                }
                else
                {
                    Crypt.make(verifying_key, verify);
                }
            });
        });
    });

    it('should maybe sign and verify JSON test vector', function (callback)
    {
        Crypt.make(get_signing_key(), function (err, sign)
        {
            if (err)
            {
                callback(err);
                return;
            }
            
            sign.maybe_sign(json_vector, function (err, sv)
            {
                if (expect_sign_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expr(expect(sv.signed, 'signed').to.be.true);

                Crypt.make(get_verifying_key(this.get_key()), function (err, verify)
                {
                    if (err)
                    {
                        callback(err);
                        return;
                    }
                    
                    verify.maybe_verify(sv, function (err, vv)
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
        });
    });

    it('should maybe not sign and verify JSON test vector', function (callback)
    {
        Crypt.make().maybe_sign(false, json_vector, function (err, sv)
        {
            expr(expect(err, 'error').not.to.exist);
            expr(expect(sv.signed, 'signed').to.be.false);

            Crypt.make(function (err, verify)
            {
                if (err)
                {
                    callback(err);
                    return;
                }
                
                verify.maybe_verify(sv, function (err, vv)
                {
                    expr(expect(err, 'error').not.to.exist);
                    expect(vv, 'verified json test vector').to.eql(json_vector);
                    callback();
                });
            });
        });
    });

    it('should support key function', function (callback)
    {
        Crypt.make(function (err, sign)
        {
            if (err)
            {
                callback(err);
                return;
            }

            sign.options.custom = 'bar';
            
            sign.maybe_sign(json_vector, function (err, sv)
            {
                expr(expect(this).not.to.equal(sign));
                expr(expect(this.options.custom).to.equal('bar'));

                if (expect_sign_error)
                {
                    expr(expect(err, 'expected error').to.exist);
                    callback();
                    return;
                }

                expr(expect(err, 'error').not.to.exist);
                expr(expect(sv.signed, 'signed').to.be.true);

                var verifying_key = get_verifying_key(this.get_key());

                Crypt.make(function (err, verify)
                {
                    if (err)
                    {
                        callback(err);
                        return;
                    }
                    
                    verify.options.custom = 'bar2';
                    
                    verify.maybe_verify(sv, function (err, vv)
                    {
                        expr(expect(this).not.to.equal(verify));
                        expr(expect(this.options.custom).to.equal('bar2'));

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
                });
            }, function (cb)
            {
                cb(null, get_signing_key());
            });
        });
    });
}

exports.setup = setup;
