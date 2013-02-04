/*global require,
         Crypt: true */

if (typeof require === 'function')
{
    Crypt = require('./index.js').Crypt;
}

var key = "0123456789012345";
var data = "foobar";

new Crypt(key).maybe_encrypt(data, function (err, edata)
{
    "use strict";

    console.log(edata);

    new Crypt(key).maybe_decrypt(edata, function (err, ddata)
    {
        if (err)
        {
            console.error(err);
        }
        else
        {
            console.log(ddata === data);
        }
    });
});

new Crypt(key).maybe_sign(data, function (err, sdata)
{
    "use strict";

    console.log(sdata);

    new Crypt(key).maybe_verify(sdata, function (err, vdata)
    {
        if (err)
        {
            console.error(err);
        }
        else
        {
            console.log(vdata === data);
        }
    });
});

// test encrypted data from browser

new Crypt(key).maybe_decrypt(
{
    encrypted: true,
    data: {
        data: "RFmwUxKgNgGDHAIF6+Flze+MOYjGjgeJSBY9GN5BYnXOWQhn+WumocA3wd1F0oKzUYtArfcWNMHKZsTcx9wd+4HwE9sdnjq399S6rRz8KRM=",
        iv: "fO4sPVhPMf2oqyokZfDKlw=="
    }
},
function (err, data)
{
    "use strict";

    if (err)
    {
        console.error(err);
    }
    else
    {
        console.log(data);
    }
});

// test signed data from browser

new Crypt(key).maybe_verify(
{
    signed: true,
    data: {
        data: '"foobar"',
        signature: 'C/k9Am99a14CtCAPrrI+/0XqieB0S+/I7dNgijTYboU='
    }
},
function (err, data)
{
    "use strict";

    if (err)
    {
        console.error(err);
    }
    else
    {
        console.log(data);
    }
});

