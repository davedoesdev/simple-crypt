/*global RSAKey: false,
         ASN1HEX: false,
         Uint8Array: false */
/*jslint browser: true, nomen: true */

function SecureRandom()
{
    "use strict";
    return undefined;
}

SecureRandom.prototype.nextBytes = function (ba)
{
    "use strict";

    var ua = new Uint8Array(ba.length), i;

    window.crypto.getRandomValues(ua);

    for (i = 0; i < ba.length; i += 1)
    {
        ba[i] = ua[i];
    }
};

var _prvKeyHead = "-----BEGIN RSA PRIVATE KEY-----";
var _prvKeyFoot = "-----END RSA PRIVATE KEY-----";
var _pubKeyHead = "-----BEGIN PUBLIC KEY-----";
var _pubKeyFoot = "-----END PUBLIC KEY-----";
/*jslint regexp: true */
var _re_pem = /(.{1,64})/g;
/*jslint regexp: false */

function _rsapem_extractEncodedData2(sPEMKey)
{
    "use strict";
    var s = sPEMKey;
    s = s.replace(_prvKeyHead, "");
    s = s.replace(_prvKeyFoot, "");
    s = s.replace(_pubKeyHead, "");
    s = s.replace(_pubKeyFoot, "");
    s = s.replace(/[ \n]+/g, "");
    return s;
}

RSAKey.prototype.readPrivateKeyFromPEMString = function (keyPEM)
{
    "use strict";
    return this.readPrivateKeyFromPkcs1PemString(_rsapem_extractEncodedData2(keyPEM));
};

RSAKey.prototype.readPublicKeyFromPEMString = function (keyPEM)
{
    "use strict";
    return this.readPublicKeyFromX509PEMString(_rsapem_extractEncodedData2(keyPEM));
};

function _asnhex_getStartPosOfV_AtObj(s, pos)
{
    "use strict";
    return ASN1HEX.getStartPosOfV_AtObj(s, pos);
}

function _asnhex_getPosOfNextSibling_AtObj(s, pos)
{
    "use strict";
    return ASN1HEX.getPosOfNextSibling_AtObj(s, pos);
}

function _asnhex_getHexOfV_AtObj(s, pos)
{
    "use strict";
    return ASN1HEX.getHexOfV_AtObj(s, pos);
}
