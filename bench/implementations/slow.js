/*global SlowCrypt: false,
         sc_sym_slow: false,
         sc_asym_priv_slow: false,
         sc_asym_pub_slow: false,
         before: false */
/*jslint node: true */
"use strict";

before(require('./common'));

module.exports = {
    encrypt_decrypt_symmetric: function (data, done)
    {
        sc_sym_slow.encrypt(data, function (err, ev)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_sym_slow.decrypt(ev, done);
        });
    },

    encrypt_decrypt_asymmetric: function (data, done)
    {
        sc_asym_pub_slow.encrypt(data, function (err, ev)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_asym_priv_slow.decrypt(ev, done);
        });
    },

    sign_verify_symmetric: function (data, done)
    {
        sc_sym_slow.sign(data, function (err, sv)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_sym_slow.verify(sv, done);

        });
    },

    sign_verify_asymmetric: function (data, done)
    {
        sc_asym_priv_slow.sign(data, function (err, sv)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_asym_pub_slow.verify(sv, done);
        });
    },

    load_rsa_privkey: function (pem, done)
    {
        SlowCrypt.make(pem, done);
    },

    derive_key_from_password: function (info, done)
    {
        SlowCrypt.make(info, done);
    }
};

