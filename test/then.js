/*global json_vector: false,
         expect: false,
         Crypt: false,
         it: false */
/*jslint node: true */
"use strict";

exports.setup = function (signing_key, encryption_key, decryption_key, verifying_key)
{
    it('should sign then encrypt followed by decrypt then verify JSON test vector', function (cb)
    {
        Crypt.sign_encrypt_sign(signing_key, encryption_key, json_vector, function (err, sev)
        {
            if (err)
            {
                cb(err);
                return;
            }

            Crypt.verify_decrypt_verify(decryption_key, verifying_key, sev, function (err, dvv)
            {
                if (err)
                {
                    cb(err);
                    return;
                }

                expect(dvv, 'decrypted and verified json test vector').to.eql(json_vector);

                cb();
            });
        });
    });
};
