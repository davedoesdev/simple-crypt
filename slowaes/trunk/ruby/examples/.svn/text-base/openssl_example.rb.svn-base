#!/usr/bin/env ruby

require 'rubygems'
require File.join(File.dirname(__FILE__), '..', 'lib', 'ruby-aes')
require 'base64'


enc = Aes.openssl_encrypt("pass", "test")
dec = Aes.openssl_decrypt("pass", enc[:salted])

puts Base64.b64encode(enc[:salted])
puts "Salt: #{enc[:salt]}"
puts "Key: #{enc[:key]}"
puts "IV: #{enc[:iv]}"

puts "Decrypted: #{dec[:raw]}"