/*global describe: false,
         priv_key: false,
         pub_key: false */
/*jslint node: true */
"use strict";

describe('encrypt_decrypt_asymmetric_priv_pub', function ()
{
    require('./encrypt_decrypt').setup(function ()
    {
        return priv_key;
    }, function ()
    {
        return pub_key;
    }, true);
});

describe('encrypt_decrypt_asymmetric_pub_priv', function ()
{
    require('./encrypt_decrypt').setup(function ()
    {
        return pub_key;
    }, function ()
    {
        return priv_key;
    });
});

