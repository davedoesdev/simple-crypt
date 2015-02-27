/*global ursa: false,
         priv_pem: false,
         pub_pem: false,
         RSAKey: false */
/*jslint node: true, nomen: true */
"use strict";

global.expect = require('chai').expect;
global.wd = require('wd');
global.ursa = require('ursa');
global.json_vector = require('./fixtures/json_vector.js');

global.priv_pem = "-----BEGIN RSA PRIVATE KEY-----\n" +
"MIIEogIBAAKCAQEA4qiw8PWs7PpnnC2BUEoDRcwXF8pq8XT1/3Hc3cuUJwX/otNe\n" +
"fr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB3sI+pFtjjLBXD/zJmuL3Afg91J9p\n" +
"79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu89d2V5x02aXB9LqdXkPwiO0eR5s/\n" +
"xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8UVXNPJnQAfaiKazF+hCdl/syrIh0K\n" +
"CZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKILwZFSvZ9iddRPQK3CtgFiBnXbVwU\n" +
"5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpjsQIDAQABAoIBAF2sU/wxvHbwAhQE\n" +
"pnXVMMcO0thtOodxzBz3JM2xThhWnVDgxCPkAhWq2X0NSm5n9BY5ajwyxYH6heTc\n" +
"p6lagtxaMONiNaE2W7TqxzMw696vhnYyL+kH2e9+owEoKucXz4QYatqsJIQPb2vM\n" +
"0h+DfFAgUvNgYNZ2b9NBsLn9oBImDfYueHyqpRGTdX5urEVtmQz029zaC+jFc7BK\n" +
"Y6qBRSTwFwnVgE+Td8UgdrO3JQ/0Iwk/lkphnhls/BYvdNC5O8oEppozNVmMV8jm\n" +
"61K+agOh1KD8ky60iQFjo3VdFpUjI+W0+sYiYpDb4+Z9OLOTK/5J2EBAGim9siyd\n" +
"gHspx+UCgYEA9+t5Rs95hG9Q+6mXn95hYduPoxdFCIFhbGl6GBIGLyHUdD8vmgwP\n" +
"dHo7Y0hnK0NyXfue0iFBYD94/fuUe7GvcXib93heJlvPx9ykEZoq9DZnhPFBlgIE\n" +
"SGeD8hClazcr9O99Fmg3e7NyTuVou+CIublWWlFyN36iamP3a08pChsCgYEA6gvT\n" +
"pi/ZkYI1JZqxXsTwzAsR1VBwYslZoicwGNjRzhvuqmqwNvK17dnSQfIrsC2VnG2E\n" +
"UbE5EIAWbibdoL4hWUpPx5Tl096OjC3qBR6okAxbVtVEY7Rmv7J9RwriXhtD1DYp\n" +
"eBvo3eQonApFkfI8Lr2kuKGIgwzkZ72QLXsKJiMCgYBZXBCci0/bglwIObqjLv6e\n" +
"zQra2BpT1H6PGv2dC3IbLvBq7hN0TQCNFTmusXwuReNFKNq4FrB/xqEPusxsQUFh\n" +
"fv2Il2QoI1OjUE364jy1RZ7Odj8TmKp+hoEykPluybYYVPIbT3kgJy/+bAXyIh5m\n" +
"Av2zFEQ86HIWMu4NSb0bHQKBgETEZNOXi52tXGBIK4Vk6DuLpRnAIMVl0+hJC2DB\n" +
"lCOzIVUBM/VxKvNP5O9rcFq7ihIEO7SlFdc7S1viH4xzUOkjZH2Hyl+OLOQTOYd3\n" +
"kp+AgfXpg8an4ujAUP7mu8xaxns7zsNzr+BCgYwXmIlhWz2Aiz2UeL/IsfOpRwuV\n" +
"801xAoGADQB84MJe/X8xSUZQzpn2KP/yZ7C517qDJjComGe3mjVxTIT5XAaa1tLy\n" +
"T4mvpSeYDJkBD8Hxr3fB1YNDWNbgwrNPGZnUTBNhxIsNLPnV8WySiW57LqVXlggH\n" +
"vjFmyDdU5Hh6ma4q+BeAqbXZSJz0cfkBcBLCSe2gIJ/QJ3YJVQI=            \n" +
"-----END RSA PRIVATE KEY-----";

global.pub_pem = "-----BEGIN PUBLIC KEY-----\n" +
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qiw8PWs7PpnnC2BUEoD\n" +
"RcwXF8pq8XT1/3Hc3cuUJwX/otNefr/Bomr3dtM0ERLN3DrepCXvuzEU5FcJVDUB\n" +
"3sI+pFtjjLBXD/zJmuL3Afg91J9p79+Dm+43cR6wuKywVJx5DJIdswF6oQDDzhwu\n" +
"89d2V5x02aXB9LqdXkPwiO0eR5s/xHXgASl+hqDdVL9hLod3iGa9nV7cElCbcl8U\n" +
"VXNPJnQAfaiKazF+hCdl/syrIh0KCZ5opggsTJibo8qFXBmG4PkT5YbhHE11wYKI\n" +
"LwZFSvZ9iddRPQK3CtgFiBnXbVwU5t67tn9pMizHgypgsfBoeoyBrpTuc4egSCpj\n" +
"sQIDAQAB\n" +
"-----END PUBLIC KEY-----";

global.priv_key = ursa.createPrivateKey(priv_pem, 'utf8');
global.pub_key = ursa.createPublicKey(pub_pem, 'utf8');

var simple_crypt = require('..');

if (process.env.SLOW)
{
    global.navigator = {
        appName: "Netscape"
    };

    global.window = {
        crypto: {
            getRandomValues: function (ua)
            {
                var buf = require('crypto').randomBytes(ua.length), i;

                for (i = 0; i < buf.length; i += 1)
                {
                    ua[i] = buf[i];
                }
            }
        },

        atob: function (a)
        {
            return String.fromCharCode.apply(String, new Buffer(a, 'base64'));
        },

        btoa: function (b)
        {
            var arr = [], i;

            for (i = 0; i < b.length; i += 1)
            {
                arr.push(b.charCodeAt(i));
            }

            return new Buffer(arr).toString('base64');
        }
    };

    var toString = String.prototype.toString;

    String.prototype.toString = function (encoding)
    {
        if (encoding === 'base64')
        {
            return global.window.btoa(this);
        }

        return toString.call(this);
    };

    /*jslint stupid: true */
    eval.call(global, require('fs').readFileSync(__dirname + '/../dist/simple-crypt-deps.js', 'utf8'));
    /*jslint stupid: false */

    global.priv_key.slow_key = new RSAKey();
    global.priv_key.slow_key.readPrivateKeyFromPEMString(priv_pem);

    global.pub_key.slow_key = new RSAKey();
    global.pub_key.slow_key.readPublicKeyFromPEMString(pub_pem);

    var parse_key = simple_crypt.SlowCrypt.parse_key;

    simple_crypt.SlowCrypt.parse_key = function (key, cb)
    {
        if (key && key.slow_key)
        {
            key = key.slow_key;
        }

        if (key && Buffer.isBuffer(key.salt))
        {
            key = Object.create(key);
            key.salt = String.fromCharCode.apply(String, key.salt);
        }

        parse_key(key, cb);
    };

    global.Crypt = simple_crypt.SlowCrypt;
}
else
{
    global.Crypt = simple_crypt.Crypt;
}
