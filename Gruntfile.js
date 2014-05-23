/*jslint node: true */
"use strict";

var mocha_options = {
    timeout: 10 * 60 * 1000,
    reporter: 'dot'
};

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        jslint: {
            files: [ 'Gruntfile.js', 'lib/*.js', 'test/*.js', 'bench/**/*.js' ],
            directives: {
                white: true
            }
        },

        concat: {
            'simple-crypt': {
                dest: 'dist/simple-crypt.js',
                src: 'lib/simple-crypt.js',
                nonull: true
            },

            'simple-crypt-deps': {
                dest: 'dist/simple-crypt-deps.js',
                src: ['slowaes/aes.js',
                      'jsrsasign/ext/cryptojs-312-core-fix.js',
                      'crypto-js/build/components/sha256.js',
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

        cafemocha: {
            all: {
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

        exec: {
            'cover-fast': {
                cmd: './node_modules/.bin/istanbul cover --dir ./coverage/fast --report none -x Gruntfile.js ./node_modules/.bin/grunt test',
                maxBuffer: 10000 * 1024
            },

            'cover-slow': {
                cmd: './node_modules/.bin/istanbul cover --dir ./coverage/slow --report none -x Gruntfile.js ./node_modules/.bin/grunt test-slow',
                maxBuffer: 10000 * 1024
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
                cmd: 'phantomjs --webdriver=4444 --webdriver-loglevel=ERROR --debug=false &'
            },

            stop_phantomjs: {
                cmd: 'pkill -g 0 phantomjs'
            },

            install: {
                cmd: 'git submodule init && git submodule update && svn checkout http://slowaes.googlecode.com/svn/trunk/js/ slowaes && wget -O pbkdf2.js http://anandam.name/pbkdf2/pbkdf2.js.txt && svn checkout http://crypto-js.googlecode.com/svn/tags/3.1.2/ crypto-js && hg clone https://bitbucket.org/adrianpasternak/js-rsa-pem && ./patches/patch.sh'
            }
        }
    });

    grunt.loadNpmTasks('grunt-jslint');
    grunt.loadNpmTasks('grunt-cafe-mocha');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-exec');
    grunt.loadNpmTasks('grunt-contrib-concat');
    grunt.loadNpmTasks('grunt-env');

    grunt.registerTask('lint', 'jslint');
    grunt.registerTask('test', ['exec:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'cafemocha:all',
                                'exec:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-slow', ['exec:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'env:slow',
                                'cafemocha:all',
                                'exec:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-browser', ['exec:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'cafemocha:browser',
                                'exec:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['exec:cover-fast', 'exec:cover-slow', 'exec:check-cover', 'exec:cover-report']);
    grunt.registerTask('coveralls', 'exec:coveralls');
    grunt.registerTask('bench', 'exec:bench');
    grunt.registerTask('bench-gfm', 'exec:bench_gfm');
    grunt.registerTask('build', ['concat:simple-crypt', 'concat:simple-crypt-deps']);
    grunt.registerTask('install', 'exec:install');
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
