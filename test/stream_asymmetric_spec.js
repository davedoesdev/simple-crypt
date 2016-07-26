/*global pub_key: false,
         priv_key: false,
         pub_pem: false,
         priv_pem: false,
         describe: false */
/*jslint node: true */
"use strict";

var stream = require('./stream');

describe('stream asymmetric', function ()
{
    stream.setup(priv_key, pub_key, priv_key, pub_key);
    stream.setup(priv_pem, pub_pem, priv_pem, pub_pem);
});
