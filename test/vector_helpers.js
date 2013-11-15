/*jslint node: true, nomen: true, forin: true */
"use strict";

var path = require('path'),
    fs = require('fs'),
    async = require('async'),
    byline = require('byline'),
    vecdir = path.join(__dirname, 'fixtures', 'NIST Known Answer Test Vectors');

exports.vecopts = { json: false, check: false, pad: false };

exports.read_aes_vectors = function (cb)
{
    var test_vectors = {};
    
    fs.readdir(vecdir, function (err, files)
    {
        if (err)
        {
            cb(err);
            return;
        }

        async.each(files, function (file, cb)
        {
            var stream = byline(fs.createReadStream(path.join(vecdir, file))),
                key = null,
                iv = null,
                plaintext = null,
                ciphertext = null;

            stream.on('data', function (l)
            {
                l = l.toString();
                var s = l.split('='),
                    item = s[0].trim(),
                    existing;

                if (item === 'COUNT')
                {
                    key = null;
                    iv = null;
                    plaintext = null;
                    ciphertext = null;
                }
                else if (item === 'KEY')
                {
                    key = s[1].trim();
                }
                else if (item === 'IV')
                {
                    iv = s[1].trim();
                }
                else if (item === 'PLAINTEXT')
                {
                    plaintext = s[1].trim();
                }
                else if (item === 'CIPHERTEXT')
                {
                    ciphertext = s[1].trim();
                }

                if ((key !== null) &&
                    (iv !== null) &&
                    (plaintext !== null) &&
                    (ciphertext !== null))
                {
                    test_vectors[key] = test_vectors[key] || {};
                    test_vectors[key][iv] = test_vectors[key][iv] || {};

                    existing = test_vectors[key][iv][plaintext];
                    
                    if ((existing !== undefined) &&
                        (existing !== ciphertext))
                    {
                        cb('conflicting test vectors detected');
                        return;
                    }

                    test_vectors[key][iv][plaintext] = ciphertext;
                }
            });

            stream.on('end', cb);
        }, function (err)
        {
            if (err)
            {
                cb(err);
                return;
            }

            cb(null, function (f, cb)
            {
                var tasks = [], key, iv, plaintext, ciphertext;

                for (key in test_vectors)
                {
                    for (iv in test_vectors[key])
                    {
                        for (plaintext in test_vectors[key][iv])
                        {
                            ciphertext = test_vectors[key][iv][plaintext];

                            tasks.push(
                            {
                                key: new Buffer(key, 'hex'),
                                iv: new Buffer(iv, 'hex'),
                                plaintext: new Buffer(plaintext, 'hex'),
                                ciphertext: new Buffer(ciphertext, 'hex')
                            });
                        }
                    }
                }

                async.eachSeries(tasks, f, cb);
            });
        });
    });
};

exports.read_hmac_vectors = function (cb)
{
    var test_vectors = {},
        stream = byline(fs.createReadStream(path.join(vecdir, 'HMAC.rsp'))),
        L = null,
        tlen = null,
        key = null,
        msg = null,
        mac = null;

    stream.on('data', function (l)
    {
        l = l.toString();
        var s = l.split('='),
            item = s[0].trim(),
            existing;

        if (l.indexOf('[L=') === 0)
        {
            L = parseInt(l.substr(3), 10);
        }
        else if (item === 'Count')
        {
            tlen = null;
            key = null;
            msg = null;
            mac = null;
        }
        else if (item === 'Tlen')
        {
            tlen = parseInt(s[1].trim(), 10);
        }
        else if (item === 'Key')
        {
            key = s[1].trim();
        }
        else if (item === 'Msg')
        {
            msg = s[1].trim();
        }
        else if (item === 'Mac')
        {
            mac = s[1].trim();
        }

        if ((L === 32) &&
            (tlen === 32) &&
            (key !== null) &&
            (msg !== null) &&
            (mac !== null))
        {
            test_vectors[key] = test_vectors[key] || {};

            existing = test_vectors[key][msg];
            
            if ((existing !== undefined) &&
                (existing !== mac))
            {
                cb('conflicting test vectors detected');
                return;
            }

            test_vectors[key][msg] = mac;
        }
    });

    stream.on('end', function (err)
    {
        if (err)
        {
            cb(err);
            return;
        }

        cb(null, function (f, cb)
        {
            var tasks = [], key, msg, mac;

            for (key in test_vectors)
            {
                for (msg in test_vectors[key])
                {
                    mac = test_vectors[key][msg];

                    tasks.push(
                    {
                        key: new Buffer(key, 'hex'),
                        msg: new Buffer(msg, 'hex'),
                        mac: new Buffer(mac, 'hex')
                    });
                }
            }

            async.eachSeries(tasks, f, cb);
        });
    });
};

