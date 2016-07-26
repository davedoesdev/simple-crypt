/*global Crypt: false,
         describe: false */
/*jslint node: true */
"use strict";

var crypto = require('crypto'),
    stream = require('./stream');

describe('stream symmetric', function ()
{
    var ed_key = crypto.randomBytes(Crypt.get_key_size()),
        sv_key = crypto.randomBytes(500);

    stream.setup(sv_key, ed_key, ed_key, sv_key);
});
