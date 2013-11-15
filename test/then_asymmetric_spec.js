/*global pub_key: false,
         priv_key: false,
         describe: false */
/*jslint node: true */
"use strict";

var then = require('./then');

describe('then asymmetric', function ()
{
    then.setup(priv_key, pub_key, priv_key, pub_key);
});
