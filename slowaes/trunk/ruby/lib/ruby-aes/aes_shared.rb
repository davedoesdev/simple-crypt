=begin
    This file is a part of ruby-aes <http://rubyforge.org/projects/ruby-aes>
    Written by Alex Boussinet <alex.boussinet@gmail.com>

    It contains the code shared by all the implementations
=end

module AesShared

  def encrypt_blocks(buffer)
    raise "Bad block length" unless (buffer.length % 16).zero?
    ct = ""
    block = ""
    buffer.each_byte do |char|
      block << char
      if block.length == 16
        ct << encrypt_block(block)
        block = ""
      end
    end
    ct
  end

  def decrypt_blocks(buffer)
    raise "Bad block length" unless (buffer.length % 16).zero?
    pt = ""
    block = ""
    buffer.each_byte do |char|
      block << char
      if block.length == 16
        pt << decrypt_block(block)
        block = ""
      end
    end
    pt
  end

  def encrypt_buffer(buffer)
    # Altered this to conform with OpenSSL padding
    ct = ''
    rounds = (buffer.length.to_f / 16).ceil
    rounds.times do |i|
      block = buffer[i*16, 16]
      if i < rounds - 1
        ct << encrypt_block(block)
      elsif block.length < 16
        m = 16 - block.length
        ct << encrypt_block(block << m.chr * m)
      else #block size is equal to 16
        ct << encrypt_block(block)
        ct << encrypt_block("\017" * 16)
      end
    end
    ct
  end

  def decrypt_buffer(buffer)
    buffer = buffer[16, buffer.length - 16]
    pt = ''
    rounds = (buffer.length.to_f / 16).ceil
    rounds.times do |i|
      block = buffer[i*16, 16]
      pt << decrypt_block(block)
    end
    m = pt[pt.length-1]
    pt = pt[0, pt.length - m]
  end
end
