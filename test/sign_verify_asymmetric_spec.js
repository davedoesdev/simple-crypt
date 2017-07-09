/*global describe: false,
         it: false,
         expect: false,
         Crypt: false,
         priv_key: false,
         pub_key: false */
/*jslint node: true */
"use strict";

describe('sign_verify_asymmetric_priv_pub', function ()
{
    require('./sign_verify').setup(function ()
    {
        return priv_key;
    }, function ()
    {
        return pub_key;
    });

    it('should support binary signatures', function (done)
    {
        Crypt.make(priv_key,
        {
            base64: false
        }, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.sign('hello', function (err, sdata)
            {
                expect(err).to.equal(null);
                if (process.env.SLOW)
                {
                    expect(typeof sdata.signature).to.equal('string');
                }
                else
                {
                    expect(Buffer.isBuffer(sdata.signature)).to.equal(true);
                }
                Crypt.make(pub_key,
                {
                    base64: false
                }, function (err, crypt)
                {
                    expect(err).to.equal(null);
                    crypt.verify(sdata, function (err, sdata)
                    {
                        expect(err).to.equal(null);
                        expect(sdata).to.equal('hello');
                        done();
                    });
                });
            });
        });
    });
});

describe('sign_verify_asymmetric_pub_priv', function ()
{
    require('./sign_verify').setup(function ()
    {
        return pub_key;
    }, function ()
    {
        return priv_key;
    }, true);
});

