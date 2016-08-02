/*global describe: false,
         it: false,
         expect: false,
         Crypt: false,
         priv_key: false,
         pub_key: false */
/*jslint node: true */
"use strict";

describe('encrypt_decrypt_asymmetric_priv_pub', function ()
{
    require('./encrypt_decrypt').setup(function ()
    {
        return priv_key;
    }, function ()
    {
        return pub_key;
    }, true);
});

describe('encrypt_decrypt_asymmetric_pub_priv', function ()
{
    require('./encrypt_decrypt').setup(function ()
    {
        return pub_key;
    }, function ()
    {
        return priv_key;
    });

    it('should support binary ekeys', function (done)
    {
        Crypt.make(pub_key,
        {
            base64: false
        }, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.encrypt('hello', function (err, edata)
            {
                expect(err).to.equal(null);
                if (process.env.SLOW)
                {
                    expect(typeof edata.ekey).to.equal('string');
                }
                else
                {
                    expect(Buffer.isBuffer(edata.ekey)).to.equal(true);
                }
                Crypt.make(priv_key,
                {
                    base64: false
                }, function (err, crypt)
                {
                    expect(err).to.equal(null);
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

