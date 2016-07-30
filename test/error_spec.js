/*global describe: false,
         it: false,
         expect: false,
         beforeEach: false,
         afterEach: false,
         Crypt: false */
/*jslint node: true */
"use strict";

var sinon = require('sinon'),
    crypto = require('crypto'),
    stream = require('stream'),
    frame = require('frame-stream');

describe('errors', function ()
{
    var key = crypto.randomBytes(Crypt.get_key_size()),
        key2 = crypto.randomBytes(Crypt.get_key_size()),
        key3 = crypto.randomBytes(Crypt.get_key_size()),
        key4 = crypto.randomBytes(Crypt.get_key_size()),
        iv = crypto.randomBytes(Crypt.get_iv_size());

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

        Crypt.make(key, function (err)
        {
            expect(err.message).to.equal('dummy error');
            cb();
        });
    });

    it('should return an error when version is not supported', function (cb)
    {
        Crypt.make(key, function (err, crypt)
        {
            if (err) { return cb(err); }
            crypt.encrypt('foobar', function (err, edata)
            {
                if (err) { return cb(err); }
                edata.version = Crypt.get_version() + 1;
                crypt.decrypt(edata, function (err)
                {
                    expect(err.message).to.equal('unsupported version');
                    crypt.sign('foobar', function (err, sdata)
                    {
                        if (err) { return cb(err); }
                        sdata.version = Crypt.get_version() + 1;
                        crypt.verify(sdata, function (err)
                        {
                            expect(err.message).to.equal('unsupported version');
                            cb();
                        });
                    });
                });
            });

        });
    });

    it('should pass on errors from dynamic key retrieval', function (done)
    {
        var crypt = Crypt.make(),
            sinon = this.sinon;

        function test(op1, op2, prop, data, done)
        {
            op1 = 'maybe_' + op1;
            op2 = 'maybe_' + op2;

            crypt[op1](true, 'foobar', function (err)
            {
                expect(err.message).to.equal('some error');
                this[op1](true, 'foobar', function (err, data2)
                {
                    expect(data2[prop]).to.equal(false);
                    expect(data2.data).to.equal('foobar');
                    this[op1](true, 'foobar', function (err)
                    {
                        expect(err.message).to.equal('dummy error');
                        this[op2](data, function (err)
                        {
                            expect(err.message).to.equal('some other error');
                            this[op2](data, function (err)
                            {
                                expect(err.message).to.equal('dummy error');
                                done();
                            }, function (cb)
                            {
                                cb(null, key);
                            });
                        }, function (cb)
                        {
                            cb(new Error('some other error'));
                        });
                    }, function (cb)
                    {
                        cb(null, key);
                    });
                }, function (cb)
                {
                    cb();
                });
            }, function (cb)
            {
                cb(new Error('some error'));    
            });
        }

        crypt.maybe_encrypt(true, 'foobar', function (err, edata)
        {
            if (err) { return done(err); }
            expect(edata.encrypted).to.equal(true);

            crypt.maybe_sign(true, 'foobar', function (err, sdata)
            {
                if (err) { return done(err); }
                expect(sdata.signed).to.equal(true);

                sinon.stub(Crypt, 'parse_key', function (key, cb)
                {
                    cb(new Error('dummy error'));
                });

                test('encrypt', 'decrypt', 'encrypted', edata, function ()
                {
                    test('sign', 'verify', 'signed', sdata, done);
                });
            }, function (cb)
            {
                cb(null, key);
            });
        }, function (cb)
        {
            cb(null, key); 
        });
    });

    it('should return errors from sign_encrypt_sign and verify_decrypt_verify',
    function (done)
    {
        var sinon = this.sinon,
            orig_make = Crypt.make;

        sinon.stub(Crypt, 'make', function (k, cb)
        {
            if (k === key)
            {
                return cb(new Error('error1'));
            }

            orig_make.call(this, k, function (err, obj)
            {
                if (err) { return done(err); }

                if (k === key2)
                {
                    sinon.stub(obj, 'sign', function (data, cb)
                    {
                        cb(new Error('error2'));
                    });

                    sinon.stub(obj, 'verify', function (data, cb)
                    {
                        cb(new Error('error2'));
                    });
                }

                if (k === key3)
                {
                    sinon.stub(obj, 'encrypt', function (data, iv, cb)
                    {
                        cb(new Error('error3'));
                    });

                    sinon.stub(obj, 'decrypt', function (data, cb)
                    {
                        cb(new Error('error3'));
                    });
                }
                
                cb(null, obj);
            });
        });

        function test(rev, method, data, cb)
        {
            Crypt[method](key, key2, data, function (err)
            {
                expect(err.message).to.equal('error1');
                Crypt[method](key2, key, data, function (err)
                {
                    expect(err.message).to.equal('error1');
                    Crypt[method](key2, key2, data, function (err)
                    {
                        expect(err.message).to.equal('error2');
                        Crypt[method](rev? key3 : key4, rev? key4 : key3, data,
                        function (err)
                        {
                            expect(err.message).to.equal('error3');
                            Crypt[method](key4, key4, data, function (err, data)
                            {
                                if (err) { return done(err); }
                                cb(data);
                            });
                        });
                    });
                });
            });
        }

        test(false, 'sign_encrypt_sign', 'hello', function (data)
        {
            test(true, 'verify_decrypt_verify', data, function (data)
            {
                expect(data).to.equal('hello');
                done();
            });
        });
    });

    it('should return stream errors', function (done)
    {
        var sinon = this.sinon,
            orig_make = Crypt.make;

        sinon.stub(Crypt, 'make', function (k, options, cb)
        {
            if (k === key)
            {
                return cb(new Error('make error'));
            }

            orig_make.call(this, k, options, function (err, obj)
            {
                if (err) { return done(err); }

                if (k === key2)
                {
                    sinon.stub(obj, 'encrypt', function (data, cb)
                    {
                        cb(new Error('out error'));
                    });

                    sinon.stub(obj, 'sign', function (data, cb)
                    {
                        cb(new Error('out error'));
                    });

                    sinon.stub(obj, 'decrypt', function (data, cb)
                    {
                        cb(new Error('in error'));
                    });

                    sinon.stub(obj, 'verify', function (data, cb)
                    {
                        cb(new Error('in error'));
                    });
                }

                cb(null, obj);
            });
        });

        function test_out(method, cb)
        {
            var s = new stream.PassThrough();

            Crypt[method + '_stream'](key, s, function (err)
            {
                expect(err.message).to.equal('make error');

                Crypt[method + '_stream'](key2, s, function (err, es)
                {
                    es.on('error', function (err)
                    {
                        expect(err.message).to.equal('out error');
                        cb();
                    });
                });

                s.end('hello');
            });
        }

        function setup_in(method, key, onerr, cb)
        {
            var s = new stream.PassThrough(),
                fs = frame.encode();

            fs.pipe(s);
            
            Crypt[method + '_stream'](key, s, function (err, ds)
            {
                expect(err).to.equal(null);
                expect(ds).to.be.an.instanceof(stream.Transform);
                ds.on('error', onerr);
                cb(fs, ds);
            });
        }

        function setup_verify(key, onerr, cb)
        {
            setup_in('verify', key, onerr, cb);
        }

        function setup_decrypt(key, onerr, cb)
        {
            setup_in('decrypt', key, onerr, cb);
        }

        function test_decrypt(cb)
        {
            var s = new stream.PassThrough();
            Crypt.decrypt_stream(key, s, function (err)
            {
                expect(err.message).to.equal('make error');
                setup_decrypt(key3, function (err)
                {
                    expect(err.message).to.equal('wrong length');
                    setup_decrypt(key3, function (err)
                    {
                        expect(err.message).to.equal('wrong length');
                        setup_decrypt(key2, function (err)
                        {
                            expect(err.message).to.equal('in error');
                            Crypt.make(key3,
                            {
                                base64: false,
                                json: false
                            },
                            function (err, encrypter)
                            {
                                expect(err).to.equal(null);
                                encrypter.encrypt('hello', iv, function (err, ev)
                                {
                                    expect(err).to.equal(null);
                                    setup_decrypt(key3, function (err)
                                    {
                                        expect(err.message).to.equal('wrong marker');
                                        encrypter.encrypt('\0hello', iv, function (err, ev)
                                        {
                                            expect(err).to.equal(null);
                                            setup_decrypt(key3, function (err)
                                            {
                                                expect(err.message).to.equal('wrong marker');
                                                setup_decrypt(key3, function (err)
                                                {
                                                    expect(err.message).to.equal('wrong order');
                                                    cb();
                                                }, function (fs, ds)
                                                {
                                                    fs.write(ev.iv, 'binary');
                                                    fs.write(ev.data, 'binary');
                                                    var buf = new Buffer(4);
                                                    buf.writeUInt32BE(Crypt.get_version());
                                                    fs.write(buf);
                                                    fs.write(new Buffer([0]));
                                                    encrypter.encrypt('\u0001hello', iv, function (err, ev)
                                                    {
                                                        expect(err).to.equal(null);
                                                        fs.write(ev.iv, 'binary');
                                                        fs.write(ev.data, 'binary');
                                                        var buf = new Buffer(4);
                                                        buf.writeUInt32BE(Crypt.get_version());
                                                        fs.write(buf);
                                                        fs.write(new Buffer([0]));
                                                    });
                                                });
                                            }, function (fs, ds)
                                            {
                                                fs.write(ev.iv, 'binary');
                                                fs.write(ev.data, 'binary');
                                                var buf = new Buffer(4);
                                                buf.writeUInt32BE(Crypt.get_version());
                                                fs.write(buf);
                                                fs.write(new Buffer([0]));
                                                fs.write(ev.iv, 'binary');
                                                fs.write(ev.data, 'binary');
                                                fs.write(buf);
                                                fs.write(new Buffer([0]));
                                            });
                                        });
                                    }, function (fs, ds)
                                    {
                                        fs.write(ev.iv, 'binary');
                                        fs.write(ev.data, 'binary');
                                        var buf = new Buffer(4);
                                        buf.writeUInt32BE(Crypt.get_version());
                                        fs.write(buf);
                                        fs.write(new Buffer([0]));
                                    });
                                });
                            });
                        }, function (fs, ds)
                        {
                            fs.write(iv);
                            fs.write('hello');
                            var buf = new Buffer(4);
                            buf.writeUInt32BE(Crypt.get_version());
                            fs.write(buf);
                            fs.write(new Buffer([0]));
                        });
                    }, function (fs, ds)
                    {
                        fs.write(iv);
                        fs.write('hello');
                        var buf = new Buffer(4);
                        buf.writeUInt32BE(Crypt.get_version());
                        fs.write(buf);
                        ds.write('');
                    });
                }, function (fs, ds)
                {
                    fs.write(iv);
                    fs.write('hello');
                    fs.write('dummy');
                });
            });
        }
        
        function test_verify(cb)
        {
            var s = new stream.PassThrough();
            Crypt.verify_stream(key, s, function (err)
            {
                expect(err.message).to.equal('make error');
                setup_verify(key3, function (err)
                {
                    expect(err.message).to.equal('wrong length');
                    setup_verify(key2, function (err)
                    {
                        expect(err.message).to.equal('in error');
                        Crypt.make(key3,
                        {
                            base64: false,
                            json: false
                        },
                        function (err, signer)
                        {
                            expect(err).to.equal(null);
                            signer.sign('hello', function (err, sv)
                            {
                                expect(err).to.equal(null);
                                setup_verify(key3, function (err)
                                {
                                    expect(err.message).to.equal('wrong marker');
                                    signer.sign('\0hello', function (err, sv)
                                    {
                                        expect(err).to.equal(null);
                                        setup_verify(key3, function (err)
                                        {
                                            expect(err.message).to.equal('wrong marker');
                                            setup_verify(key3, function (err)
                                            {
                                                expect(err.message).to.equal('wrong order');
                                                cb();
                                            }, function (fs, ds)
                                            {
                                                fs.write(sv.signature, 'binary');
                                                fs.write(sv.data, 'binary');
                                                var buf = new Buffer(4);
                                                buf.writeUInt32BE(Crypt.get_version());
                                                fs.write(buf);
                                                signer.sign('\u0001hello', function (err, sv)
                                                {
                                                    expect(err).to.equal(null);
                                                    fs.write(sv.signature, 'binary');
                                                    fs.write(sv.data, 'binary');
                                                    var buf = new Buffer(4);
                                                    buf.writeUInt32BE(Crypt.get_version());
                                                    fs.write(buf);
                                                });
                                            });
                                        }, function (fs, ds)
                                        {
                                            fs.write(sv.signature, 'binary');
                                            fs.write(sv.data, 'binary');
                                            var buf = new Buffer(4);
                                            buf.writeUInt32BE(Crypt.get_version());
                                            fs.write(buf);
                                            fs.write(sv.signature, 'binary');
                                            fs.write(sv.data, 'binary');
                                            fs.write(buf);
                                        });
                                    });
                                }, function (fs, ds)
                                {
                                    fs.write(sv.signature, 'binary');
                                    fs.write(sv.data, 'binary');
                                    var buf = new Buffer(4);
                                    buf.writeUInt32BE(Crypt.get_version());
                                    fs.write(buf);
                                });
                            });
                        });
                    }, function (fs, ds)
                    {
                        fs.write('sig');
                        fs.write('hello');
                        var buf = new Buffer(4);
                        buf.writeUInt32BE(Crypt.get_version());
                        fs.write(buf);
                    });
                }, function (fs, ds)
                {
                    fs.write('sig');
                    fs.write('hello');
                    fs.write('dummy');
                });
            });
        }

        test_out('encrypt', function ()
        {
            test_decrypt(function ()
            {
                test_out('sign', function ()
                {
                    test_verify(done);
                });
            });
        });
    });
});

