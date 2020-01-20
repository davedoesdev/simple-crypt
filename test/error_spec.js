/*global describe: false,
         it: false,
         expect: false,
         beforeEach: false,
         afterEach: false,
         Crypt: false,
         pub_key: false,
         priv_key: false */
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
        this.sinon = sinon.createSandbox();
    });

    afterEach(function ()
    {
        this.sinon.restore();
    });

    it('should return an error when constructing if parse_key errors', function (cb)
    {
        this.sinon.stub(Crypt, 'parse_key').callsFake(function (key, cb)
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

                sinon.stub(Crypt, 'parse_key').callsFake(function (key, cb)
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

        sinon.stub(Crypt, 'make').callsFake(function (k, cb)
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
                    sinon.stub(obj, 'sign').callsFake(function (data, cb)
                    {
                        cb(new Error('error2'));
                    });

                    sinon.stub(obj, 'verify').callsFake(function (data, cb)
                    {
                        cb(new Error('error2'));
                    });
                }

                if (k === key3)
                {
                    sinon.stub(obj, 'encrypt').callsFake(function (data, iv, cb)
                    {
                        cb(new Error('error3'));
                    });

                    sinon.stub(obj, 'decrypt').callsFake(function (data, cb)
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

        sinon.stub(Crypt, 'make').callsFake(function (k, options, cb)
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
                    sinon.stub(obj, 'encrypt').callsFake(function (data, cb)
                    {
                        cb(new Error('out error'));
                    });

                    sinon.stub(obj, 'sign').callsFake(function (data, cb)
                    {
                        cb(new Error('out error'));
                    });

                    sinon.stub(obj, 'decrypt').callsFake(function (data, cb)
                    {
                        cb(new Error('in error'));
                    });

                    sinon.stub(obj, 'verify').callsFake(function (data, cb)
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

        function test_in(method, cb)
        {
            var s = new stream.PassThrough();
            Crypt[method + '_stream'](key, s, function (err)
            {
                expect(err.message).to.equal('make error');
                Crypt[method + '_stream'](key3, s, { maxSize: 64 * 1024 },
                function (err, in_s)
                {
                    expect(err).to.equal(null);
                    expect(in_s).to.be.an.instanceof(stream.Transform);
                    in_s.on('error', function (err)
                    {
                        expect(err.message).to.equal('Message is larger than the allowed maximum of 65536');
                        cb();
                    });
                    s.write(Buffer.from([0xff, 0xff, 0xff, 0xff]));
                });
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
            test_in('decrypt', function ()
            {
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
                                                    var buf = Buffer.alloc(4);
                                                    buf.writeUInt32BE(Crypt.get_version());
                                                    fs.write(buf);
                                                    fs.write(Buffer.from([0]));
                                                    encrypter.encrypt('\u0001hello', iv, function (err, ev)
                                                    {
                                                        expect(err).to.equal(null);
                                                        fs.write(ev.iv, 'binary');
                                                        fs.write(ev.data, 'binary');
                                                        var buf = Buffer.alloc(4);
                                                        buf.writeUInt32BE(Crypt.get_version());
                                                        fs.write(buf);
                                                        fs.write(Buffer.from([0]));
                                                    });
                                                });
                                            }, function (fs, ds)
                                            {
                                                fs.write(ev.iv, 'binary');
                                                fs.write(ev.data, 'binary');
                                                var buf = Buffer.alloc(4);
                                                buf.writeUInt32BE(Crypt.get_version());
                                                fs.write(buf);
                                                fs.write(Buffer.from([0]));
                                                fs.write(ev.iv, 'binary');
                                                fs.write(ev.data, 'binary');
                                                fs.write(buf);
                                                fs.write(Buffer.from([0]));
                                            });
                                        });
                                    }, function (fs, ds)
                                    {
                                        fs.write(ev.iv, 'binary');
                                        fs.write(ev.data, 'binary');
                                        var buf = Buffer.alloc(4);
                                        buf.writeUInt32BE(Crypt.get_version());
                                        fs.write(buf);
                                        fs.write(Buffer.from([0]));
                                    });
                                });
                            });
                        }, function (fs, ds)
                        {
                            fs.write(iv);
                            fs.write('hello');
                            var buf = Buffer.alloc(4);
                            buf.writeUInt32BE(Crypt.get_version());
                            fs.write(buf);
                            fs.write(Buffer.from([0]));
                        });
                    }, function (fs, ds)
                    {
                        fs.write(iv);
                        fs.write('hello');
                        var buf = Buffer.alloc(4);
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
            test_in('verify', function ()
            {
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
                                                var buf = Buffer.alloc(4);
                                                buf.writeUInt32BE(Crypt.get_version());
                                                fs.write(buf);
                                                signer.sign('\u0001hello', function (err, sv)
                                                {
                                                    expect(err).to.equal(null);
                                                    fs.write(sv.signature, 'binary');
                                                    fs.write(sv.data, 'binary');
                                                    var buf = Buffer.alloc(4);
                                                    buf.writeUInt32BE(Crypt.get_version());
                                                    fs.write(buf);
                                                });
                                            });
                                        }, function (fs, ds)
                                        {
                                            fs.write(sv.signature, 'binary');
                                            fs.write(sv.data, 'binary');
                                            var buf = Buffer.alloc(4);
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
                                    var buf = Buffer.alloc(4);
                                    buf.writeUInt32BE(Crypt.get_version());
                                    fs.write(buf);
                                });
                            });
                        });
                    }, function (fs, ds)
                    {
                        fs.write('sig');
                        fs.write('hello');
                        var buf = Buffer.alloc(4);
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

    it('should return x then y stream errors', function (done)
    {
        var sinon = this.sinon,
            orig = {};

        function sv_stub(method)
        {
            orig[method + '_stream'] = Crypt[method + '_stream'];

            sinon.stub(Crypt, method + '_stream').callsFake(function (k, s, options, cb)
            {
                if (k === key)
                {
                    return cb(new Error('sv error'));
                }

                if (k === key3)
                {
                    if (options.key3ed)
                    {
                        return cb(new Error('sv error 2'));
                    }

                    options.key3ed = true;
                }

                orig[method + '_stream'].call(this, k, s, options, function (err, obj)
                {
                    if (err) { return done(err); }

                    if (k === key4)
                    {
                        setTimeout(function ()
                        {
                            obj.emit('error', new Error('sv error 3'));
                        }, 250);
                    }

                    cb(null, obj);
                });
            });
        }

        sv_stub('sign');
        sv_stub('verify');

        function ed_stub(method)
        {
            orig[method + '_stream'] = Crypt[method + '_stream'];

            sinon.stub(Crypt, method + '_stream').callsFake(function (k, s, options, cb)
            {
                if (k === key2)
                {
                    return cb(new Error('ed error'));
                }

                orig[method + '_stream'].call(this, k, s, options, function (err, obj)
                {
                    if (err) { return done(err); }

                    if (k === key4)
                    {
                        setTimeout(function ()
                        {
                            obj.emit('error', new Error('ed error 2'));
                        }, 250);
                    }

                    cb(null, obj);
                });
            });
        }

        ed_stub('encrypt');
        ed_stub('decrypt');

        function test(method, done)
        {
            var s = new stream.PassThrough();
            method += '_stream';
            Crypt[method](key, key, s, {}, function (err)
            {
                expect(err.message).to.equal('sv error');
                Crypt[method](key2, key2, s, {}, function (err)
                {
                    expect(err.message).to.equal('ed error');
                    Crypt[method](key3, key3, s, {}, function (err)
                    {
                        expect(err.message).to.equal('sv error 2');
                        Crypt[method](key4, key4, s, {}, function (err, out_s)
                        {
                            expect(err).to.equal(null);
                            expect(out_s).to.be.an.instanceof(stream.Transform);
                            var errs = [];
                            out_s.on('error', function (err)
                            {
                                errs.push(err.message);
                                expect(errs.length).to.be.at.most(3);
                                if (errs.length === 3)
                                {
                                    expect(errs).to.eql([
                                        'sv error 3',
                                        'ed error 2',
                                        'sv error 3'
                                    ]);
                                    done();
                                }
                            });
                        });
                    });
                });
            });
        }

        test('sign_encrypt_sign', function ()
        {
            test('verify_decrypt_verify', done);
        });
    });

    it('should treat -----BEGIN but not PUBLIC/PRIVATE KEY as a symmetric key', function (done)
    {
        var key = '-----BEGIN KEY  ';
        Crypt.make(key, function (err, crypt)
        {
            expect(err).to.equal(null);
            if (process.env.SLOW)
            {
                expect(Buffer.from(crypt.key).toString('binary')).to.equal(key);
            }
            else
            {
                expect(crypt.key.export().toString('binary')).to.equal(key);
            }
            crypt.encrypt('hello', function (err, edata)
            {
                expect(err).to.equal(null);
                crypt.decrypt(edata, function (err, data)
                {
                    expect(err).to.equal(null);
                    expect(data).to.equal('hello');
                    done();
                });
            });
        });
    });

    it('should return pbkdf2 errors', function (done)
    {
        if (process.env.SLOW)
        {
            Crypt.make(
            {
                password: { length: 1 }
            }, function (err)
            {
                expect(err.message).to.be.oneOf([
                    'input.charCodeAt is not a function',
                    'undefined is not a function'
                ]);
                done();
            });
        }
        else
        {
            var sinon = this.sinon;

            Crypt.make(
            {
                password: 'foo',
                iterations: 'hello'
            }, function (err)
            {
                expect(err.message).to.be.oneOf([
                    'Iterations not a number',
                    'The "iterations" argument must be of type number. Received type string',
                    'The "iterations" argument must be of type number. Received type string (\'hello\')'

                ]);

                sinon.stub(crypto, 'pbkdf2').callsFake(function (password, salt, iterations, keylen, digest, callback)
                {
                    callback(new Error('dummy error'));
                });
                
                Crypt.make(
                {
                    password: 'foo'
                }, function (err)
                {
                    expect(err.message).to.equal('dummy error');

                    crypto.pbkdf2.restore();
                    sinon.stub(crypto, 'pbkdf2').callsFake(function ()
                    {
                        throw('dummy error 2');
                    });

                    Crypt.make(
                    {
                        password: 'foo'
                    }, function (err)
                    {
                        expect(err.message).to.equal('dummy error 2');
                        done();
                    });
                });
            });
        }
    });

    it('should error if try to decrypt with a public key', function (done)
    {
        Crypt.make(pub_key, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.decrypt(
            {
                version: Crypt.get_version()
            }, function (err)
            {
                expect(err.message).to.equal("can't decrypt using public key");
                done();
            });
        });
    });

    it("should error if encrypted digest doesn't match", function (done)
    {
        Crypt.make(crypto.randomBytes(Crypt.get_key_size()), 
        {
            base64: false,
            json: false
        }, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.encrypt(Buffer.from('hello'), function (err, edata)
            {
                expect(err).to.equal(null);
                if (process.env.SLOW)
                {
                    edata.data = 'A' + edata.data.substr(1);
                }
                else
                {
                    edata.data[0] = ~edata.data[0];
                }
                crypt.decrypt(edata, function (err)
                {
                    expect(err.message).to.equal('digest mismatch');
                    done();
                });
            });
        });
    });

    it('should error if try to verify using private key', function (done)
    {
        Crypt.make(priv_key,
        {
            base64: false
        }, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.verify(
            {
                version: Crypt.get_version(),
                data: [0]
            }, function (err)
            {
                expect(err.message).to.equal("can't verify using private key");
                done();
            });
        });
    });

    it('should error if signature length is wrong', function (done)
    {
        Crypt.make(key,
        {
            base64: false 
        }, function (err, crypt)
        {
            expect(err).to.equal(null);
            crypt.sign(Buffer.from('hello'), function (err, sdata)
            {
                sdata.signature = process.env.SLOW ?
                        sdata.signature + '\0' :
                        Buffer.concat([sdata.signature, Buffer.from([0])]);
                crypt.verify(sdata, function (err)
                {
                    expect(err.message).to.equal('digest mismatch');
                    done();
                });
            });
        });
    });
});

