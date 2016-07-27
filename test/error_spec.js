/*global describe: false,
         it: false,
         expect: false,
         beforeEach: false,
         afterEach: false,
         Crypt: false */
/*jslint node: true */
"use strict";

var sinon = require('sinon');

describe('errors', function ()
{
    beforeEach(function ()
    {
        this.sinon = sinon.sandbox.create();
    });

    afterEach(function ()
    {
        this.sinon.restore();
    });

    it('should return an error when constructing if parse_key errors', function (cb)
    {
        this.sinon.stub(Crypt, 'parse_key', function (key, cb)
        {
            cb(new Error('dummy error'));
        });

        Crypt.make('dummy key', function (err)
        {
            expect(err.message).to.equal('dummy error');
            cb();
        });
    });
});

