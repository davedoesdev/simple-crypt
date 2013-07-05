/*jslint es5: true, unparam: true */
/*global require,
         Crypt: true */

if (typeof require === 'function')
{
    Crypt = require('./index.js').Crypt;
}

var priv_key = "-----BEGIN RSA PRIVATE KEY-----                 \n\
MIIEpAIBAAKCAQEAziHpUknf3JJwMq98iglS+3ueGUbC8F7LCnHJQ8yWMaTfwMp0\n\
JpB6fTFvX/HoaLL0qa0rZdcmDiU7/v6PpI8HaFs/KqPVPuJzVL0oi2d6RlN0hG+w\n\
2RwddVweKSyqn7smnRuVk8PPAsQcBnheNn7NEa9wuGEEEDd6RbrTg0GBNEBtfuSQ\n\
yUPMfvBW/eX56OIpIzE1qMUDNJYHoMUrqMya1Qd0QA0bKtoCIbY5ev/p3eGUGKTD\n\
Fg+NrhdaHyJDukKbQaMiGeC+2Cp3gaeIQj+nONrNTfgVPkOrkC+GWvZeAqNHuCRE\n\
8J3ANPkf3FspnZ1ASlrsTh5RVOzHE0M9MZ9GlwIDAQABAoIBADs6lT82yOMpFKIL\n\
uH41RanLEFd09Kh6pF7A6TLZA0MKe9x6j7tRAlEctkLcUIpc+V4Tywd9NYsU+dNA\n\
M+f1zQwYQ+MtpiVmjfsISzEbL5ArhKxVJ3yKzpAdQvFTy0cQUH0OIwGNXtsNnHvj\n\
dDa2Ypg1T+86uR8rwa9tij8JwGVRpXJEmELG0WgLASz7aCMbzrsQcAkQLM4SSXxk\n\
NL3lC6oYOe6aeakWvNYq+GxPysGChJlTFAyjn72QNm2eCypF+wz4Bf2Cr9yMv1ch\n\
bYOz3CuM5iZp3W53kKrQnZIoJj9z90Z6k+uy7SdXLKA8T5wUaVU4XJEs+I1xecb6\n\
G0YWz6ECgYEA+R2BZUBs3GwQgXMon2y4oWbpiLndxJXfkGxzLMJMfkzAl4IC+spJ\n\
/KGvjSZUCCNrhWmqLGqHfywe6txNcML/5+sINoVFfflj6/gtSuHgKb6pSQ67UOGP\n\
+CS5YJZwtRxqUXmhV0mahDgegQrLbEV6VcGx9SUfyzQqcx3XZsCy9hECgYEA09RN\n\
UPuMv+H7iXd7ViCyz4s98L/4zAqSM4VuDZu/IOF1elHZIMALsU9cKV69+aoTcMxE\n\
GmRaxJPjhrbM7bc6XNYmEz4G3PzIv7b7VsT3zkqqblr/Uk/9tUNy4SwhYWWnye7u\n\
PRvtpenKNk+xbd1q6FYliSUxq6gzpkuH8qktKicCgYBzu7h0wMSSdwYIDecugcUY\n\
/wW6Bpe4D+ToZOnxPmdpOeEzwiv+NWLAIqG7UrYxfbsjJR7xOaCvfWDzvdugaoeX\n\
SELtiWbqiqVYaFkqc9u/qRtenKB7h/9pyi3xaJL+ITBnn7lMIx7NFIFfdBNjvreC\n\
BdXWTSQDNL4P8yoyS44Y8QKBgQC8c2NVaHUPQDxHT8SqGuz5Nycjx6XP4JewvkPq\n\
V2TyG6In8Cj6ud+tHq0fIOph8qzY7OCpmh4mRGtmrboiwZ9qeBnnhIcWks0FwgRY\n\
bWMIY+S7yLjcwc00NY0+RcRsocNkIuxP8Ui7EgKTztJKq3EwwXMjT7Ogw0Mv7oJD\n\
n75OgQKBgQDtWjDBqsNG1gXyP+EQX3AlPsGydHE4Mqli1kAUiY9NrGcgdNlQMmeZ\n\
Axg7ktf4g3TAtga3pE54u+KavYnMCO5N8kZHWtpvMp5bvLf6CBq9ArVgY0X2NATC\n\
SiA7GuFBH2aih65FzTkWQKfpNczoWEa5RyetSOROk282KOXmeO5y8g==        \n\
-----END RSA PRIVATE KEY-----";

var pub_key = "-----BEGIN PUBLIC KEY-----                       \n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAziHpUknf3JJwMq98iglS\n\
+3ueGUbC8F7LCnHJQ8yWMaTfwMp0JpB6fTFvX/HoaLL0qa0rZdcmDiU7/v6PpI8H\n\
aFs/KqPVPuJzVL0oi2d6RlN0hG+w2RwddVweKSyqn7smnRuVk8PPAsQcBnheNn7N\n\
Ea9wuGEEEDd6RbrTg0GBNEBtfuSQyUPMfvBW/eX56OIpIzE1qMUDNJYHoMUrqMya\n\
1Qd0QA0bKtoCIbY5ev/p3eGUGKTDFg+NrhdaHyJDukKbQaMiGeC+2Cp3gaeIQj+n\n\
ONrNTfgVPkOrkC+GWvZeAqNHuCRE8J3ANPkf3FspnZ1ASlrsTh5RVOzHE0M9MZ9G\n\
lwIDAQAB                                                        \n\
-----END PUBLIC KEY-----";

var data = "foobar";

new Crypt(pub_key).maybe_encrypt(data, function (err, edata)
{
    "use strict";

    console.log(edata);

    new Crypt(priv_key).maybe_decrypt(edata, function (err, ddata)
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

new Crypt(priv_key).maybe_sign(data, function (err, sdata)
{
    "use strict";

    console.log(sdata);

    new Crypt(pub_key).maybe_verify(sdata, function (err, vdata)
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

new Crypt(priv_key).maybe_decrypt(
{
    encrypted: true,
    data: {
        data: "pDioRMvu2/HfvG30ZDO5+wnPCW3cb1jxg8rpmqoQE8tdS20fLaUFCmSwaguxvL8UM3hH3Wu3ogAK/Gav7VOdfItHpNDm1BAU95hxxqDsk80=",
        ekey: "rURikrf6C7MssEV9hnTCN4TnrQ+3LnukNRVLfJiFqMh7QIDeINI0X+6ZVXX/9xoR//ERCQgw/90EQRgDs6ZRkRz9VOQkkrhX6NtxKY/v7PULb8LNWhAHjNBxGtmfqS3Y/BfOz0C0M4gts8y93qySgWvVFw3Wtn0dYfJ+6TL6TbZ9GVAzWbJha6L36Ig1VydmnnowlQS0p2T+u7TcDFlQjksf+BKkGqqZhAozBIKJIRAdnycFQcw4vYjEy7QGI43Rk5krdzUuQPm9UyVllqfmQYHb2feD/cWaxif/cKi2hcz3A00wHX/mwgDLXscJNa4KffNqcvIx8WbGwvNyfv+loQ==",
        iv: "ialcBtIDwvYTVGk95rxmRw=="
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
new Crypt(pub_key).maybe_verify(
{
    signed: true,
    data: {
        data: '"foobar"',
        signature: "kT4OPQaB/cfQ9VxBabHniMMmZunFCk9VfyxyRnB/1cbfs1362gpKQ1YqtYq7sYUaw5vjE4IeAGU2DczUZ4hXA6KRwkGawscBNAWTwG5//kwwFCD4Z0on85S6EFLoO7VTvjZNnwh35SD5MntzMnoRUST1A/NQ05q0zgxUi9BxBvAkaKF9MXjKTAUBsBgJ7GtlOMKafp/jRxO5yAkcpHhfDbHDeEKi+8vdkTVWOfdtTOxC95tAN6Te/BxZBzbw+sRH9qw4xQPDgr7am7Ma+cSc/wYTISk3UbBIlHpKjz9pddOlIb3VdWHczHblF6rZfJpTbeLxzzIJZbpS32Qo9N1m1A=="
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

// test performance

function test_sign(i, n, d)
{
    "use strict";

    if (i === n)
    {
        console.log('asym sign: ' + (new Date() - d));
        return;
    }

    new Crypt(priv_key).maybe_sign(data, function (err, sdata)
    {
        new Crypt(pub_key).maybe_verify(sdata, function (err, vdata)
        {
            if (err)
            {
                console.error(err);
            }
            else
            {
                setTimeout(function () { test_sign(i + 1, n, d); }, 0);
            }
        });
    });
}

function test_encrypt(i, n, d)
{
    "use strict";

    if (i === n)
    {
        console.log('asym enc: ' + (new Date() - d));
        test_sign(0, n, new Date());
        return;
    }

    new Crypt(pub_key).maybe_encrypt(data, function (err, edata)
    {
        new Crypt(priv_key).maybe_decrypt(edata, function (err, ddata)
        {
            if (err)
            {
                console.error(err);
            }
            else
            {
                setTimeout(function () { test_encrypt(i + 1, n, d); }, 0);
            }
        });
    });
}

test_encrypt(0, 5000, new Date());

