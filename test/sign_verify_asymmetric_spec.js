/*global describe: false,
         priv_key: false,
         pub_key: false */
/*jslint node: true */
"use strict";

describe('sign_verify_asymmetric_priv_pub', function ()
{
    require('./sign_verify').setup(function ()
    {
        return priv_key;
    }, function ()
    {
        return pub_key;
    });
});

describe('sign_verify_asymmetric_pub_priv', function ()
{
    require('./sign_verify').setup(function ()
    {
        return pub_key;
    }, function ()
    {
        return priv_key;
    }, true);
});

