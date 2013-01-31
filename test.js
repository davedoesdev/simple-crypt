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
        data: "nC/t3gFEx/0c4Jn6asXrYh4kaCSWk8j5JkifrtS+jS6FtiAxLEggeIP5GpO07yu8V46w/7eMSD1WRd5uPw8q3adtt5N2qXiUEzXcisPdvf0=",
        iv: "N9wq83DtJC4IEiwH1FqiOg=="
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

