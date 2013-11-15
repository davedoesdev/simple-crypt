/*global SlowCrypt: false,
         FastCrypt: false,
         Crypt: false,
         priv_pem: false,
         pub_pem: false */
/*jslint node: true */

process.env.SLOW = 'yes';
var crypto = require('crypto');
require('../../../test/_common.js');

var simple_crypt = require('../../..');
global.FastCrypt = simple_crypt.Crypt;
global.SlowCrypt = simple_crypt.SlowCrypt;

global.sc_sym_fast = new FastCrypt(crypto.randomBytes(Crypt.get_key_size()));
global.sc_asym_priv_fast = new FastCrypt(priv_pem);
global.sc_asym_pub_fast = new FastCrypt(pub_pem);

global.sc_sym_slow = new SlowCrypt(crypto.randomBytes(Crypt.get_key_size()));
global.sc_asym_priv_slow = new SlowCrypt(priv_pem);
global.sc_asym_pub_slow = new SlowCrypt(pub_pem);
