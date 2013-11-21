/*global json_vector: false,
         Crypt: false,
         window: false,
         before: false,
         it: false,
         after: false,
         priv_pem: false,
         pub_pem: false,
         wd: false,
         expect: false,
         describe: false */
/*jslint node: true */
"use strict";
function expr(v) { return v; }

var crypto = require('crypto'),
    vector_helpers = require('./vector_helpers');

describe('browser', function ()
{
    var run_aes_tasks, run_hmac_tasks, browser, i,
        ed_key = crypto.randomBytes(Crypt.get_key_size()),
        sv_key = crypto.randomBytes(500),

    in_browser = function (f /*, args..., test, cb*/)
    {
        var test = arguments[arguments.length - 2],
            cb = arguments[arguments.length - 1],

        f2 = function (f /*, args..., done*/)
        {
            var r = {},
                done = arguments[arguments.length - 1];

            try
            {
                f.apply(this, Array.prototype.slice.call(arguments, 1, arguments.length - 1).concat([
                function (err)
                {
                    if (err)
                    {
                        r.err = err.stack || err.toString();
                    }
                    else
                    {
                        r.vals = Array.prototype.slice.call(arguments, 1);
                    }

                    done(r);
                }]));
            }
            catch (ex)
            {
                r.err = ex.stack;
                done(r);
            }
        };

        browser.executeAsync('return ' + f2 + '.apply(this, [' + f + '].concat(Array.prototype.slice.call(arguments)))',
                        Array.prototype.slice.call(arguments, 1, arguments.length - 2),
        function (err, r)
        {
            if (err)
            {
                cb(err);
                return;
            }

            if (r.err)
            {
                cb(r.err);
                return;
            }

            try
            {
                test.apply(this, r.vals.concat([cb]));
            }
            catch (ex)
            {
                cb(ex);
            }
        });
    },

    make_cb = function (cb, expect_error)
    {
        return function (err, v)
        {
            if (expect_error)
            {
                cb(err ? undefined : 'expected error');
                return;
            }

            if (err)
            {
                cb(err);
                return;
            }

            cb(null, v);
        };
    },

    encode_key = function (key)
    {
        var type = typeof key;

        if (type === 'string')
        {
            return new Buffer(key).toString('base64');
        }

        if (key.password)
        {
            return key;
        }

        return key.toString('base64');
    },

    setup_encrypt_decrypt = function (encrypt_key, decrypt_key, expect_error, decrypt_error, copy_salt)
    {
        decrypt_key = decrypt_key || encrypt_key;

        var asym = typeof encrypt_key === 'string';
        
        it('should encrypt and decrypt JSON test vector, asym=' + asym, function (cb)
        {
            in_browser(function (encrypt_key, decrypt_key, copy_salt, json_vector, cb)
            {
                encrypt_key = typeof encrypt_key === 'string' ? window.atob(encrypt_key) : encrypt_key;
                decrypt_key = typeof decrypt_key === 'string' ? window.atob(decrypt_key) : decrypt_key;

                Crypt.make(encrypt_key, function (err, crypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    crypt.encrypt(json_vector, function (err, ev)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !decrypt_key.salt)
                        {
                            decrypt_key = Object.create(decrypt_key);
                            decrypt_key.salt = this.get_key().salt;
                        }

                        var decrypt = function (err, ths)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }

                            ths.decrypt(ev, function (err, dv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                Crypt.make(decrypt_key, function (err, decrypt)
                                {
                                    if (err)
                                    {
                                        cb(err);
                                        return;
                                    }
                                    
                                    decrypt.decrypt(ev, function (err, dv2)
                                    {
                                        if (err)
                                        {
                                            cb(err);
                                            return;
                                        }

                                        cb(null, dv, dv2);
                                    });
                                });
                            });
                        };

                        if (decrypt_key === this.key)
                        {
                            decrypt(null, this);
                        }
                        else
                        {
                            Crypt.make(decrypt_key, decrypt);
                        }
                    });
                });
            },
            encode_key(encrypt_key),
            encode_key(decrypt_key),
            copy_salt,
            json_vector,
            function (dv, dv2, cb)
            {
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                expect(dv2, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should maybe encrypt and decrypt JSON test vector, asym=' + asym, function (cb)
        {
            in_browser(function (encrypt_key, decrypt_key, copy_salt, json_vector, cb)
            {
                encrypt_key = typeof encrypt_key === 'string' ? window.atob(encrypt_key) : encrypt_key;
                decrypt_key = typeof decrypt_key === 'string' ? window.atob(decrypt_key) : decrypt_key;

                Crypt.make(encrypt_key, function (err, crypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                
                    crypt.maybe_encrypt(json_vector, function (err, ev)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !decrypt_key.salt)
                        {
                            decrypt_key = Object.create(decrypt_key);
                            decrypt_key.salt = this.get_key().salt;
                        }

                        Crypt.make(decrypt_key, function (err, decrypt)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            decrypt.maybe_decrypt(ev, function (err, dv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, ev, dv);
                            });
                        });
                    });
                });
            },
            encode_key(encrypt_key),
            encode_key(decrypt_key),
            copy_salt,
            json_vector,
            function (ev, dv, cb)
            {
                expr(expect(ev.encrypted, 'encrypted').to.be.true);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should maybe not encrypt and decrypt JSON test vector, asym=' + asym, function (cb)
        {
            in_browser(function (json_vector, cb)
            {
                Crypt.make(function (err, encrypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    encrypt.maybe_encrypt(false, json_vector, function (err, ev)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        Crypt.make(function (err, decrypt)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            decrypt.maybe_decrypt(ev, function (err, dv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, ev, dv);
                            });
                        });
                    });
                });
            },
            json_vector,
            function (ev, dv, cb)
            {
                expr(expect(ev.encrypted, 'encrypted').to.be.false);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb));
        });

        it('should support key function, asym=' + asym, function (cb)
        {
            in_browser(function (encrypt_key, decrypt_key, copy_salt, json_vector, cb)
            {
                encrypt_key = typeof encrypt_key === 'string' ? window.atob(encrypt_key) : encrypt_key;
                decrypt_key = typeof decrypt_key === 'string' ? window.atob(decrypt_key) : decrypt_key;

                Crypt.make(function (err, encrypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    encrypt.maybe_encrypt(json_vector, function (err, ev)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !decrypt_key.salt)
                        {
                            decrypt_key = Object.create(decrypt_key);
                            decrypt_key.salt = this.get_key().salt;
                        }

                        Crypt.make(function (err, decrypt)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            decrypt.maybe_decrypt(ev, function (err, dv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, ev, dv);
                            }, function (cb)
                            {
                                cb(null, decrypt_key);
                            });
                        });
                    }, function (cb)
                    {
                        cb(null, encrypt_key);
                    });
                });
            },
            encode_key(encrypt_key),
            encode_key(decrypt_key),
            copy_salt,
            json_vector,
            function (ev, dv, cb)
            {
                expr(expect(ev.encrypted, 'encrypted').to.be.true);
                expect(dv, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should encrypt in Node and decrypt in browser, asym=' + asym, function (cb)
        {
            Crypt.make(encrypt_key, function (err, crypt)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                crypt.encrypt(json_vector, function (err, ev)
                {
                    if (expect_error && !decrypt_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);

                    in_browser(function (ev, decrypt_key, salt, cb)
                    {
                        decrypt_key = typeof decrypt_key === 'string' ? window.atob(decrypt_key) : decrypt_key;

                        if (salt)
                        {
                            decrypt_key.salt = window.atob(salt);
                        }

                        Crypt.make(decrypt_key, function (err, decrypt)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            decrypt.decrypt(ev, cb);
                        });
                    },
                    ev,
                    encode_key(decrypt_key),
                    copy_salt ? this.get_key().salt.toString('base64') : undefined,
                    function (dv, cb)
                    {
                        expect(dv, 'decrypted json test vector').to.eql(json_vector);
                        cb();
                    },
                    make_cb(cb, decrypt_error));
                });
            });
        });

        it('should encrypt in browser and decrypt in Node, asym=' + asym, function (cb)
        {
            in_browser(function (encrypt_key, copy_salt, json_vector, cb)
            {
                encrypt_key = typeof encrypt_key === 'string' ? window.atob(encrypt_key) : encrypt_key;
                Crypt.make(encrypt_key, function (err, encrypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    encrypt.encrypt(json_vector, function (err, ev)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        cb(null, copy_salt ? window.btoa(this.get_key().salt) : undefined, ev);
                    });
                });
            },
            encode_key(encrypt_key),
            copy_salt,
            json_vector,
            function (salt, ev, cb)
            {
                if (salt)
                {
                    decrypt_key = Object.create(decrypt_key);
                    decrypt_key.salt = new Buffer(salt, 'base64');
                }

                Crypt.make(decrypt_key, function (err, decrypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    decrypt.decrypt(ev, function (err, dv)
                    {
                        try
                        {
                            expr(expect(err, 'error').not.to.exist);
                            expect(dv, 'decrypted json test vector').to.eql(json_vector);
                            cb();
                        }
                        catch (ex)
                        {
                            cb(ex);
                        }
                    });
                });
            },
            make_cb(cb, expect_error));
        });
    },
    
    setup_sign_verify = function (signing_key, verifying_key, expect_error, verify_error, copy_salt)
    {
        verifying_key = verifying_key || signing_key;

        var asym = typeof verifying_key === 'string';

        it('should sign and verify JSON test_vector, asym=' + asym, function (cb)
        {
            in_browser(function (signing_key, verifying_key, copy_salt, json_vector, cb)
            {
                signing_key = typeof signing_key === 'string' ? window.atob(signing_key) : signing_key;
                verifying_key = typeof verifying_key === 'string' ? window.atob(verifying_key) : verifying_key;

                Crypt.make(signing_key, function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.sign(json_vector, function (err, sv)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !verifying_key.salt)
                        {
                            verifying_key = Object.create(verifying_key);
                            verifying_key.salt = this.get_key().salt;
                        }

                        var verify = function (err, ths)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }

                            ths.verify(sv, function (err, vv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                Crypt.make(verifying_key, function (err, verify)
                                {
                                    if (err)
                                    {
                                        cb(err);
                                        return;
                                    }
                                    
                                    verify.verify(sv, function (err, vv2)
                                    {
                                        if (err)
                                        {
                                            cb(err);
                                            return;
                                        }

                                        cb(null, vv, vv2);
                                    });
                                });
                            });
                        };

                        if (verifying_key === this.key)
                        {
                            verify(null, this);
                        }
                        else
                        {
                            Crypt.make(verifying_key, verify);
                        }
                    });
                });
            },
            encode_key(signing_key),
            encode_key(verifying_key),
            copy_salt,
            json_vector,
            function (vv, vv2, cb)
            {
                expect(vv, 'verified json test vector').to.eql(json_vector);
                expect(vv2, 'verified json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should maybe sign and verify JSON test vector, asym=' + asym, function (cb)
        {
            in_browser(function (signing_key, verifying_key, copy_salt, json_vector, cb)
            {
                signing_key = typeof signing_key === 'string' ? window.atob(signing_key) : signing_key;
                verifying_key = typeof verifying_key === 'string' ? window.atob(verifying_key) : verifying_key;

                Crypt.make(signing_key, function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.maybe_sign(json_vector, function (err, sv)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !verifying_key.salt)
                        {
                            verifying_key = Object.create(verifying_key);
                            verifying_key.salt = this.get_key().salt;
                        }

                        Crypt.make(verifying_key, function (err, verify)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            verify.maybe_verify(sv, function (err, vv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, sv, vv);
                            });
                        });
                    });
                });
            },
            encode_key(signing_key),
            encode_key(verifying_key),
            copy_salt,
            json_vector,
            function (sv, vv, cb)
            {
                expr(expect(sv.signed, 'signed').to.be.true);
                expect(vv, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should maybe not sign and verify JSON test vector, asym=' + asym, function (cb)
        {
            in_browser(function (json_vector, cb)
            {
                Crypt.make(function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.maybe_sign(false, json_vector, function (err, sv)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        Crypt.make(function (err, verify)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            verify.maybe_verify(sv, function (err, vv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, sv, vv);
                            });
                        });
                    });
                });
            },
            json_vector,
            function (sv, vv, cb)
            {
                expr(expect(sv.signed, 'signed').to.be.false);
                expect(vv, 'verified json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb));
        });

        it('should support key function, asym=' + asym, function (cb)
        {
            in_browser(function (signing_key, verifying_key, copy_salt, json_vector, cb)
            {
                signing_key = typeof signing_key === 'string' ? window.atob(signing_key) : signing_key;
                verifying_key = typeof verifying_key === 'string' ? window.atob(verifying_key) : verifying_key;

                Crypt.make(function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.maybe_sign(json_vector, function (err, sv)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        if (copy_salt && !verifying_key.salt)
                        {
                            verifying_key = Object.create(verifying_key);
                            verifying_key.salt = this.get_key().salt;
                        }

                        Crypt.make(function (err, verify)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            verify.maybe_verify(sv, function (err, vv)
                            {
                                if (err)
                                {
                                    cb(err);
                                    return;
                                }

                                cb(null, sv, vv);
                            }, function (cb)
                            {
                                cb(null, verifying_key);
                            });
                        });
                    }, function (cb)
                    {
                        cb(null, signing_key);
                    });
                });
            },
            encode_key(signing_key),
            encode_key(verifying_key),
            copy_salt,
            json_vector,
            function (sv, vv, cb)
            {
                expr(expect(sv.signed, 'signed').to.be.true);
                expect(vv, 'decrypted json test vector').to.eql(json_vector);
                cb();
            },
            make_cb(cb, expect_error));
        });

        it('should sign in Node and verify in browser, asym=' + asym, function (cb)
        {
            Crypt.make(signing_key, function (err, sign)
            {
                if (err)
                {
                    cb(err);
                    return;
                }
                
                sign.sign(json_vector, function (err, sv)
                {
                    if (expect_error && !verify_error)
                    {
                        expr(expect(err, 'expected error').to.exist);
                        cb();
                        return;
                    }

                    expr(expect(err, 'error').not.to.exist);

                    in_browser(function (sv, verifying_key, salt, cb)
                    {
                        verifying_key = typeof verifying_key === 'string' ? window.atob(verifying_key) : verifying_key;

                        if (salt)
                        {
                            verifying_key.salt = window.atob(salt);
                        }

                        Crypt.make(verifying_key, function (err, verify)
                        {
                            if (err)
                            {
                                cb(err);
                                return;
                            }
                            
                            verify.verify(sv, cb);
                        });
                    },
                    sv,
                    encode_key(verifying_key),
                    copy_salt ? this.get_key().salt.toString('base64') : undefined,
                    function (vv, cb)
                    {
                        expect(vv, 'verified json test vector').to.eql(json_vector);
                        cb();
                    },
                    make_cb(cb, verify_error));
                });
            });
        });

        it('should sign in browser and verify in Node, asym=' + asym, function (cb)
        {
            in_browser(function (signing_key, copy_salt, json_vector, cb)
            {
                signing_key = typeof signing_key === 'string' ? window.atob(signing_key) : signing_key;
                Crypt.make(signing_key, function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.sign(json_vector, function (err, sv)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        cb(null, copy_salt ? window.btoa(this.get_key().salt) : undefined, sv);
                    });
                });
            },
            encode_key(signing_key),
            copy_salt,
            json_vector,
            function (salt, sv, cb)
            {
                if (salt)
                {
                    verifying_key = Object.create(verifying_key);
                    verifying_key.salt = new Buffer(salt, 'base64');
                }

                Crypt.make(verifying_key, function (err, verify)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    verify.verify(sv, function (err, vv)
                    {
                        try
                        {
                            expr(expect(err, 'error').not.to.exist);
                            expect(vv, 'verified json test vector').to.eql(json_vector);
                            cb();
                        }
                        catch (ex)
                        {
                            cb(ex);
                        }
                    });
                });
            },
            make_cb(cb, expect_error));
        });
    },
    
    setup_then = function (signing_key, encryption_key, decryption_key, verifying_key)
    {
        it('should sign then encrypt followed by decrypt then verify JSON test vector', function (cb)
        {
            in_browser(function (signing_key, encryption_key, decryption_key, verifying_key, json_vector, cb)
            {
                signing_key = typeof signing_key === 'string' ? window.atob(signing_key) : signing_key;
                encryption_key = typeof encryption_key === 'string' ? window.atob(encryption_key) : encryption_key;
                decryption_key = typeof decryption_key === 'string' ? window.atob(decryption_key) : decryption_key;
                verifying_key = typeof verifying_key === 'string' ? window.atob(verifying_key) : verifying_key;

                Crypt.sign_encrypt_sign(signing_key, encryption_key, json_vector, function (err, sev)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }

                    Crypt.verify_decrypt_verify(decryption_key, verifying_key, sev, cb);
                });
            },
            encode_key(signing_key),
            encode_key(encryption_key),
            encode_key(decryption_key),
            encode_key(verifying_key),
            json_vector,
            function (dvv)
            {
                expect(dvv, 'decrypted and verified json test vector').to.eql(json_vector);

                cb();
            },
            cb);
        });
    };
    
    before(function (cb)
    {
        vector_helpers.read_aes_vectors(function (err, rt)
        {
            if (err)
            {
                cb(err);
                return;
            }

            run_aes_tasks = rt;
            cb();
        });
    });

    before(function (cb)
    {
        vector_helpers.read_hmac_vectors(function (err, rt)
        {
            if (err)
            {
                cb(err);
                return;
            }

            run_hmac_tasks = rt;
            cb();
        });
    });

    before(function (cb)
    {
        browser = wd.remote();

        browser.init({ browserName: 'phantomjs' }, function (err)
        {
            if (err)
            {
                cb(err);
                return;
            }

            browser.get('test/fixtures/loader.html', function (err)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                cb();
            });
        });
    });

    after(function ()
    {
        browser.quit();
    });

    it('should encrypt AES test vector plaintext and produce expected ciphertext', function (cb)
    {
        run_aes_tasks(function (task, cb)
        {
            in_browser(function (key, iv, plaintext, opts, cb)
            {
                key = window.atob(key);
                iv = window.atob(iv);
                plaintext = window.atob(plaintext);

                Crypt.make(key, opts, function (err, crypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    crypt.encrypt(plaintext, iv, cb);
                });
            }, 
            task.key.toString('base64'),
            task.iv.toString('base64'),
            task.plaintext.toString('base64'),
            vector_helpers.vecopts,
            function (v, cb)
            {
                expect(v.data, 'expected ciphertext').to.equal(task.ciphertext.toString('base64'));
                cb();
            },
            cb);
        }, cb);
    });

    it('should decrypt AES test vector ciphertext and produce expected plaintext', function (cb)
    {
        run_aes_tasks(function (task, cb)
        {
            in_browser(function (key, iv, ciphertext, opts, cb)
            {
                key = window.atob(key);

                Crypt.make(key, opts, function (err, decrypt)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    decrypt.decrypt(
                    {
                        iv: iv,
                        data: ciphertext,
                        version: Crypt.get_version()
                    }, function (err, v)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        cb(null, window.btoa(v));
                    });
                });
            }, 
            task.key.toString('base64'),
            task.iv.toString('base64'),
            task.ciphertext.toString('base64'),
            vector_helpers.vecopts,
            function (v, cb)
            {
                expect(v, 'expected plaintext').to.equal(task.plaintext.toString('base64'));
                cb();
            },
            cb);
        }, cb);
    });

    setup_encrypt_decrypt(crypto.randomBytes(Crypt.get_key_size()));
    setup_encrypt_decrypt(priv_pem, pub_pem, true);
    setup_encrypt_decrypt(pub_pem, priv_pem);

    setup_encrypt_decrypt(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    });

    setup_encrypt_decrypt(
    {
        password: 'pass1',
        iterations: 4000
    },
    {
        password: 'pass1',
        iterations: 4000
    }, true, true);

    setup_encrypt_decrypt(
    {
        password: 'pass1',
        iterations: 4000
    },
    {
        password: 'pass1',
        iterations: 4000
    }, false, false, true);

    setup_encrypt_decrypt(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4001
    }, true, true);

    setup_encrypt_decrypt(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some other salt',
        iterations: 4000
    }, true, true);

    it('should sign test vector message and produce expected mac', function (cb)
    {
        run_hmac_tasks(function (task, cb)
        {
            in_browser(function (key, msg, opts, cb)
            {
                key = window.atob(key);
                msg = window.atob(msg);

                Crypt.make(key, opts, function (err, sign)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    sign.sign(msg, cb);
                });
            },
            task.key.toString('base64'),
            task.msg.toString('base64'),
            vector_helpers.vecopts,
            function (v, cb)
            {
                expect(v.signature, 'expected mac').to.equal(task.mac.toString('base64'));
                cb();
            },
            cb);
        }, cb);
    });

    it('should verify test vector mac', function (cb)
    {
        run_hmac_tasks(function (task, cb)
        {
            in_browser(function (key, msg, mac, opts, cb)
            {
                Crypt.make(window.atob(key), opts, function (err, verify)
                {
                    if (err)
                    {
                        cb(err);
                        return;
                    }
                    
                    verify.verify(
                    {
                        data: msg,
                        signature: mac,
                        version: Crypt.get_version()
                    }, function (err, v)
                    {
                        if (err)
                        {
                            cb(err);
                            return;
                        }

                        cb(null, window.btoa(v));
                    });
                });
            },
            task.key.toString('base64'),
            task.msg.toString('base64'),
            task.mac.toString('base64'),
            vector_helpers.vecopts,
            function (v, cb)
            {
                expect(v, 'expected msg').to.equal(task.msg.toString('base64'));
                cb();
            },
            cb);
        }, cb);
    });

    for (i = 1; i < 64; i += 1)
    {
        setup_sign_verify(crypto.randomBytes(i));
    }
    
    setup_sign_verify(priv_pem, pub_pem);
    setup_sign_verify(pub_pem, priv_pem, true);

    setup_sign_verify(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    });

    setup_sign_verify(
    {
        password: 'pass1',
        iterations: 4000
    },
    {
        password: 'pass1',
        iterations: 4000
    }, true, true);

    setup_sign_verify(
    {
        password: 'pass1',
        iterations: 4000
    },
    {
        password: 'pass1',
        iterations: 4000
    }, false, false, true);

    setup_sign_verify(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4001
    }, true, true);

    setup_sign_verify(
    {
        password: 'some random password',
        salt: 'some salt value',
        iterations: 4000
    },
    {
        password: 'some random password',
        salt: 'some other salt',
        iterations: 4000
    }, true, true);

    setup_then(sv_key, ed_key, ed_key, sv_key);
    setup_then(priv_pem, pub_pem, priv_pem, pub_pem);
});
