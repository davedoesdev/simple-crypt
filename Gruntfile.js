/*jslint node: true */
"use strict";

var mocha_options = {
    timeout: 10 * 60 * 1000,
    reporter: 'dot',
    bail: true
};

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        jshint: {
            src: [ 'Gruntfile.js', 'lib/*.js', 'test/*.js', 'bench/**/*.js' ]
        },

        concat: {
            'simple-crypt': {
                dest: 'dist/simple-crypt.js',
                src: 'lib/simple-crypt.js',
                nonull: true
            },

            'simple-crypt-deps': {
                dest: 'dist/simple-crypt-deps.js',
                src: ['slowaes/trunk/js/aes.js',
                      'jsrsasign/ext/cj/cryptojs-312-core-fix.js',
                      'jsrsasign/ext/cj/sha256.js',
                      'pbkdf2.js',
                      'jsrsasign/ext/jsbn.js',
                      'jsrsasign/ext/jsbn2.js',
                      'jsrsasign/ext/base64.js',
                      'jsrsasign/ext/sha1.js',
                      'jsrsasign/ext/sha256.js',
                      'jsrsasign/ext/rsa.js',
                      'jsrsasign/ext/rsa2.js',
                      'jsrsasign/asn1hex-1.1.js',
                      'jsrsasign/base64x-1.1.js',
                      'jsrsasign/crypto-1.1.js',
                      'jsrsasign/rsasign-1.2.js',
                      'js-rsa-pem/rsa-pem.js',
                      'lib/adapt.js'],
                nonull: true
            }
        },

        env: {
            slow: {
                SLOW: 'yes'
            }
        },

        mochaTest: {
            default: {
                src: 'test/*.js',
                options: mocha_options
            },

            browser: {
                src: ['test/_common.js', 'test/browser_spec.js'],
                options: mocha_options
            }
        },

        apidox: {
            input: 'lib/docs.js',
            output: 'README.md',
            fullSourceDescription: true,
            inputTitle: false,
            extraHeadingLevels: 1,
            sections: {
                'Crypt.prototype.maybe_encrypt': '\n## Conditional and dynamic key operations',
                'Crypt.sign_encrypt_sign': '\n## Sign-encrypt-sign',
                'Crypt.prototype.sign': '\n## Signing',
                'Crypt.prototype.encrypt': '\n## Encryption',
                'Crypt.make': '\n## Create',
                'Crypt.get_key_size': '\n## Key functions',
                '': '-----'
            }
        },

        bgShell: {
            'cover-fast': {
                cmd: './node_modules/.bin/istanbul cover --dir ./coverage/fast --report none -x Gruntfile.js ./node_modules/.bin/grunt test',
                execOpts: {
                    maxBuffer: 10000 * 1024
                }
            },

            'cover-slow': {
                cmd: './node_modules/.bin/istanbul cover --dir ./coverage/slow --report none -x Gruntfile.js ./node_modules/.bin/grunt test-slow',
                execOpts: {
                    maxBuffer: 10000 * 1024
                }
            },

            'check-cover': {
                cmd: './node_modules/.bin/istanbul check-coverage --statement 80 --branch 80 --function 80 --line 80'
            },

            'cover-report': {
                cmd: './node_modules/.bin/istanbul report'
            },

            coveralls: {
                cmd: 'cat coverage/lcov.info | coveralls'
            },

            bench: {
                cmd: './node_modules/.bin/bench -c 1000,derive_key_from_password:10 -i "$(echo bench/implementations/*.js | tr " " ,)"'
            },

            bench_gfm: {
                cmd: './node_modules/.bin/bench -R gfm -c 1000,derive_key_from_password:10 -i "$(echo bench/implementations/*.js | tr " " ,)"'
            },

            start_phantomjs: {
                cmd: './node_modules/.bin/phantomjs --webdriver=4444 --webdriver-loglevel=ERROR --debug=false',
                bg: true
            },

            stop_phantomjs: {
                cmd: 'pkill -g 0 phantomjs'
            },

            install: {
                cmd: 'git submodule init && ' +
                     'git submodule update && ' +
                     'wget -nv -O slowaes.zip https://storage.googleapis.com/google-code-archive-source/v2/code.google.com/slowaes/source-archive.zip && ' +
                     'unzip -q slowaes.zip && ' +
                     'rm -f slowaes.zip && ' +
                     'wget -nv -O pbkdf2.js http://anandam.name/pbkdf2/pbkdf2.js.txt && ' +
                     'hg clone https://bitbucket.org/adrianpasternak/js-rsa-pem',
                fail: true
            }
        }
    });

    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-mocha-test');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-bg-shell');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-env');

    grunt.registerTask('lint', 'jshint');
    grunt.registerTask('test', ['bgShell:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'mochaTest:default',
                                'bgShell:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-slow', ['bgShell:start_phantomjs',
                                     'sleep:10000',
                                     'usetheforce_on',
                                     'env:slow',
                                     'mochaTest:default',
                                     'bgShell:stop_phantomjs',
                                     'usetheforce_restore']);
    grunt.registerTask('test-browser', ['bgShell:start_phantomjs',
                                        'sleep:10000',
                                        'usetheforce_on',
                                        'mochaTest:browser',
                                        'bgShell:stop_phantomjs',
                                        'usetheforce_restore']);
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['bgShell:cover-fast', 'bgShell:cover-slow', 'bgShell:check-cover', 'bgShell:cover-report']);
    grunt.registerTask('coveralls', 'bgShell:coveralls');
    grunt.registerTask('bench', 'bgShell:bench');
    grunt.registerTask('bench-gfm', 'bgShell:bench_gfm');
    grunt.registerTask('build', ['concat:simple-crypt', 'concat:simple-crypt-deps']);
    grunt.registerTask('install', 'bgShell:install');
    grunt.registerTask('default', ['lint', 'test']);

    grunt.registerTask('sleep', function (ms)
    {
        setTimeout(this.async(), ms);
    });

    // http://stackoverflow.com/questions/16612495/continue-certain-tasks-in-grunt-even-if-one-fails

    grunt.registerTask('usetheforce_on',
                       'force the force option on if needed',
    function()
    {
        if (!grunt.option('force'))
        {
            grunt.config.set('usetheforce_set', true);
            grunt.option('force', true);
        }
    });
   
    grunt.registerTask('usetheforce_restore',
                       'turn force option off if we have previously set it', 
    function()
    {
        if (grunt.config.get('usetheforce_set'))
        {
            grunt.option('force', false);

            if (grunt.fail.warncount > 0)
            {
                grunt.fail.warn('previous warnings detected');
            }
        }
    });
};
