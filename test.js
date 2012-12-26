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

// test encrypted data from browser

new Crypt(key).maybe_decrypt(
{
    encrypted: true,
    data: {
        data: "UC2Am5G0J2DpJqRUaqXO8A8eRj7CfDI9zNAtTeK2gGMLCfCXUPeIVCuWHNx8krH04SQdQjVDpbXLmf5HPcRMCdQzetmceombNsdZT842O0U=",
        iv: "VteNLCjURzvupgVAYi9Xog=="
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

