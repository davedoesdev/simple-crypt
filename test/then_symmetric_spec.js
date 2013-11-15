/*global describe: false,
         Crypt: false */
/*jslint node: true */
"use strict";

var crypto = require('crypto'),
    then = require('./then');

describe('then symmetric', function ()
{
    var ed_key = crypto.randomBytes(Crypt.get_key_size()),
        sv_key = crypto.randomBytes(500);

    then.setup(sv_key, ed_key, ed_key, sv_key);
});
