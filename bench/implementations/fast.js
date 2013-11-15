/*global FastCrypt: false,
         sc_sym_fast: false,
         sc_asym_pub_fast: false,
         sc_asym_priv_fast: false */
/*jslint node: true */
"use strict";

require('./common');

module.exports = {
    encrypt_decrypt_symmetric: function (data, done)
    {
        sc_sym_fast.encrypt(data, function (err, ev)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_sym_fast.decrypt(ev, done);
        });
    },

    encrypt_decrypt_asymmetric: function (data, done)
    {
        sc_asym_pub_fast.encrypt(data, function (err, ev)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_asym_priv_fast.decrypt(ev, done);
        });
    },

    sign_verify_symmetric: function (data, done)
    {
        sc_sym_fast.sign(data, function (err, sv)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_sym_fast.verify(sv, done);

        });
    },

    sign_verify_asymmetric: function (data, done)
    {
        sc_asym_priv_fast.sign(data, function (err, sv)
        {
            if (err)
            {
                done(err);
                return;
            }

            sc_asym_pub_fast.verify(sv, done);
        });
    },

    load_rsa_privkey: function (pem, done)
    {
        done(null, new FastCrypt(pem));
    },

    derive_key_from_password: function (info, done)
    {
        done(null, new FastCrypt(info));
    }
};

