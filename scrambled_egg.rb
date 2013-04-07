#!/usr/bin/env ruby

=begin
	[ Scrambled Egg V2 ]
	Copyright (C) 2013, Cristi Constantin.
	All Rights Reserved.
=end

require "openssl"
require "base64"
require "json"
require "zlib"

=begin
	Some documentation here...
=end

SCRAMBLE = {
	:None=> 'N',
	:ROT13=> 'R',
	:ZLIB=> 'ZL',
	#:BZ2=> 'BZ',
	#:Snappy=> 'S',
	#:QlzRuby=> 'Q',
	#:LzoRuby=> 'L',
}

ENC = {
	'None'=> 'N',
	'AES-256-CFB'=> 'AES',
	'BF-CFB'=> 'B',
	'CAMELLIA-256-CFB'=> 'CAM',
	'CAST5-CFB'=> 'CST',
	'DES-EDE3-CFB8'=> 'DES',
	'RC4-40'=> 'RC',
}

ENCODE = {
	:Base64=> '64',
	:HEX=> 'H',
	:Json=> 'JS',
	:XML=> 'XML'
}

#

class ScrambledEgg

	def initialize

		@_pre  = ''  # Current operations.
		@_enc  = ''
		@_post = ''
		@_error = '' # Error string.
		@_salt1 = '!scrambled-egg!'
		@_salt2 = '^Scrambled-Egg Encryption-Salt!$'

	end #initialize


	def _error(step, pre, enc, post, field='R')

		if step == 2
			enc += ' (ERROR!)'
		elsif step == 3
			post += ' (ERROR!)'
		else
			if field == 'R'
			  pre += ' (ERROR!)'
			else
			  pre += ' (IGNORED!)'
			end
		end

		if field == 'R'
			@_error = ' Decryption mode   step 1: #{pre} ,   step 2: #{enc} ,   step 3: #{post}'
		else
			@_error = ' Encryption mode   step 1: #{pre} ,   step 2: #{enc} ,   step 3: #{post}'
		end

	end #_error


	def encrypt(text, pre, enc, post, pwd)#, tags=true)
		puts "Encrypting pre: #{pre}, enc: #{enc}, post: #{post}."

		# Scramble operation.
		if pre == :None
			nil
		elsif pre == :ROT13
			text = text.tr("A-Za-z", "N-ZA-Mn-za-m")
		elsif pre == :ZLIB
			text = Zlib::Deflate.deflate(text)
		elsif pre == :BZ2
			text = BZ2.compress(text)
		elsif pre == :Snappy
			text = Snappy.compress(text)
		elsif pre == :QlzRuby
			text = QlzRuby.compress(text)
		elsif pre == :LzoRuby
			text = LzoRuby.compress(text)
		else
			fail 'Invalid scramble "%s" !' % [pre]
		end

		# Encryption operation.
		if enc == 'None'
			encrypted = text
		else
			begin
				o = OpenSSL::Cipher::Cipher.new(enc)
			rescue
				fail 'Invalid cipher algorithm "%s" !' % [enc]
			end
			o.encrypt
			o.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=pwd, salt=@_salt1, iter=512, keylen=32)
			o.iv  = @_salt2
			encrypted = o.update(text)
			encrypted << o.final
			o = nil
		end

		edict = {:pre=> SCRAMBLE[pre], :enc=> ENC[enc], :post=> ENCODE[post]}

		# Encoding operation.
		if post == :Base64
			edict[:text] = Base64.strict_encode64(encrypted)
			final = '<@>%{pre}:%{enc}:%{post}<@>%{text}' % edict
		elsif post == :HEX
			# Hexencode is faster than `string.unpack('H*')`
			edict[:text] = Digest.hexencode(encrypted)
			final = '<@>%{pre}:%{enc}:%{post}<@>%{text}' % edict
		elsif post == :Json
			edict[:text] = Base64.strict_encode64(encrypted)
			final = '{"pre": "%{pre}", "enc": "%{enc}", "post": "%{post}", "data": "%{text}"}' % edict
		elsif post == :XML
			edict[:text] = Base64.strict_encode64(encrypted)
			final = "<root>\n<pre>%{pre}</pre><enc>%{enc}</enc><post>%{post}</post>\n<data>%{text}</data>\n</root>" % edict
		else
			fail 'Invalid codec "%s" !' % [post]
		end

		return final

	end #encrypt


	def decrypt(text, pre, enc, post, pwd)
		puts "Decrypting pre: #{pre}, enc: #{enc}, post: #{post}."

		# Un-decode operation.
		if pre == :Base64
			text.gsub!(/\<@>.+\<@>/, '')
			text = Base64.strict_decode64(text)
		elsif pre == :HEX
			text.gsub!(/\<@>.+\<@>/, '')
			text = [text].pack('H*')
		elsif pre == :Json
			text = JSON::load(text)['data']
			text = Base64.strict_decode64(text)
		elsif pre == :XML
			text.gsub!('<root>', '')
			text.gsub!('</root>', '')
			text.gsub!('<data>', '')
			text.gsub!('</data>', '')
			text.gsub!(/\<pre>.+\<\/post>/, '')
			text = Base64.decode64(text)
		else
			fail 'Invalid codec "%s" !' % [pre]
		end

		# Decryption operation.
		if enc == 'None'
			decrypted = text
		else
			begin
				o = OpenSSL::Cipher::Cipher.new(enc)
			rescue
				fail 'Invalid cipher algorithm "%s" !' % [enc]
			end
			o.decrypt
			o.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=pwd, salt=@_salt1, iter=512, keylen=32)
			o.iv  = @_salt2
			decrypted = o.update(text)
			decrypted << o.final
			o = nil
		end

		# Scramble operation.
		if post == :None
			final = decrypted
		elsif post == :ROT13
			final = decrypted.tr("A-Za-z", "N-ZA-Mn-za-m")
		elsif post == :ZLIB
			final = Zlib::Inflate.inflate(decrypted)
		elsif post == :BZ2
			final = BZ2.decompress(decrypted)
		elsif post == :Snappy
			final = Snappy.decompress(decrypted)
		elsif post == :QlzRuby
			final = QlzRuby.cdeompress(decrypted)
		elsif post == :LzoRuby
			final = LzoRuby.decompress(decrypted)
		else
			fail 'Invalid scramble "%s" !' % [post]
		end

		return final

	end #decrypt


	def _import(pre, enc, post, pwd, fpath, decrypt=true)

	puts "Not implemented"

	end #_import


	def _export(pre, enc, post, pwd)

	puts "Not implemented"

	end #_export


end #class

#

if __FILE__ == $0

end

# Eof()
