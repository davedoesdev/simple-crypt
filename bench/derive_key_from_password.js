/*global implementation: false */
/*jslint node: true, unparam: true */
"use strict";

module.exports = function (i, done)
{
    implementation.derive_key_from_password(
    {
        password: 'PassW0rd!',
        iterations: 2000
    }, done);
};
