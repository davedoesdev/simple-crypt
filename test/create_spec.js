/*global describe: false,
         it: false,
         expect: false,
         Crypt: false */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

describe('create', function ()
{
    var default_opts = {
        json: true,
        check: true,
        pad: true,
        custom: undefined
    };

    it('should create with no arguments', function ()
    {
        var crypt = Crypt.make();
        expr(expect(crypt.key).not.to.exist);
        expect(crypt.options).to.eql(default_opts);
    });

    it('should create with just options', function ()
    {
        var opts = {
            json: false,
            check: false,
            pad: false,
            custom: 42
        },

        crypt = Crypt.make(opts);

        expect(crypt.options).not.to.equal(opts);
        expect(crypt.options).to.eql(opts);
    });

    it('should create with just a callback', function (cb)
    {
        Crypt.make(function (err, crypt)
        {
            if (err) { return cb(err); }
            expr(expect(crypt.key).not.to.exist);
            expect(crypt.options).to.eql(default_opts);
            cb();
        });
    });
 
    it('should create with a key and a callback', function (cb)
    {
        Crypt.make('some key', function (err, crypt)
        {
            if (err) { return cb(err); }
            expect(process.env.SLOW ? String.fromCharCode.apply(String, crypt.key) : crypt.key).to.equal('some key');
            expect(crypt.options).to.eql(default_opts);
            cb();
        });
    });

    it('should create with a key, options and a callback', function (cb)
    {
        var opts = {
            json: false,
            check: false,
            pad: false,
            custom: 42
        };

        Crypt.make('another key', opts, function (err, crypt)
        {
            if (err) { return err; }
            expect(process.env.SLOW ? String.fromCharCode.apply(String, crypt.key) : crypt.key).to.equal('another key');
            expect(crypt.options).to.eql(opts);
            cb();
        });
    });
});

