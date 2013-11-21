/*global SlowCrypt: false,
         FastCrypt: false,
         Crypt: false,
         priv_pem: false,
         pub_pem: false */
/*jslint node: true, unparam: true */

process.env.SLOW = 'yes';
var crypto = require('crypto');
require('../../../test/_common.js');

var simple_crypt = require('../../..');
global.FastCrypt = simple_crypt.Crypt;
global.SlowCrypt = simple_crypt.SlowCrypt;

var async = require('async');

function setter(cb, name)
{
    "use strict";

    return function (err, crypt)
    {
        if (err)
        {
            cb(err);
            return;
        }

        global[name] = crypt;
        cb(null, crypt);
    };
}

module.exports = function (times, cb)
{
    "use strict";
    
    async.parallel([
        function (cb)
        {
            FastCrypt.make(crypto.randomBytes(Crypt.get_key_size()),
                           setter(cb, 'sc_sym_fast'));
        },
        function (cb)
        {
            FastCrypt.make(priv_pem, setter(cb, 'sc_asym_priv_fast'));
        },
        function (cb)
        {
            FastCrypt.make(pub_pem, setter(cb, 'sc_asym_pub_fast'));
        },
        function (cb)
        {
            SlowCrypt.make(crypto.randomBytes(Crypt.get_key_size()),
                           setter(cb, 'sc_sym_slow'));
        },
        function (cb)
        {
            SlowCrypt.make(priv_pem, setter(cb, 'sc_asym_priv_slow'));
        },
        function (cb)
        {
            SlowCrypt.make(pub_pem, setter(cb, 'sc_asym_pub_slow'));
        }
    ], cb);
};

