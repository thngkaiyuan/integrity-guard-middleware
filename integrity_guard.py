from hashlib import sha256
from aead import AEAD
from django.http import HttpResponse

import os
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Pkcs1_cipher

import random
from base64 import b64encode
from base64 import b64decode
from base64 import urlsafe_b64decode
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from urllib import unquote_plus

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class IntegrityGuard:
	def __init__(self):
		self.log_file = open('/home/django/error.log','a')
		with open('/home/django/key') as f:
			pub_key2 = f.read()
		pub_key_obj2 = RSA.importKey(pub_key2)
		self.cipher = Pkcs1_cipher.new(pub_key_obj2)

	def log(self, msg):
		self.log_file.write("[LOG]: " + msg + '\n')
		self.log_file.flush()

	def unpad(self, s):
		return s[:-ord(s[len(s)-1:])]

	def encrypt(self, key, plaintext, associated_data):
		# Generate a random 96-bit IV.
		iv = os.urandom(12)

		# Construct an AES-GCM Cipher object with the given key and a
		# randomly generated IV.
		encryptor = Cipher(
			algorithms.AES(key),
			modes.GCM(iv),
			backend=default_backend()
		).encryptor()

		# associated_data will be authenticated but not encrypted,
		# it must also be passed in on decryption.
		encryptor.authenticate_additional_data(associated_data)

		# Encrypt the plaintext and get the associated ciphertext.
		# GCM does not require padding.
		ciphertext = encryptor.update(plaintext) + encryptor.finalize()

		return iv + ciphertext + encryptor.tag

	def process_request(self, request):
		request.symmetric_key_ = None
		header_name = 'HTTP_X_SECURE_HEADER'
		if header_name not in request.META:
			return
		try:
			secure_header = request.META[header_name]
			enc_key, ciphertext = secure_header.split('; ')
			enc_key = b64decode(enc_key[2::])
			ciphertext = b64decode(ciphertext[2::])

			# decrypt enc_key using RSA private key
			sentinel = os.urandom(32)
			sym_key = self.cipher.decrypt(enc_key, sentinel)
			self.log("Sym key: %s" % sym_key.encode('hex'))

			# use key to decrypt ciphertext to raw_dec_request
			iv = ciphertext[:AES.block_size]
			ciphertext = ciphertext[AES.block_size::]
			decryption_suite = AES.new(sym_key, AES.MODE_CBC, iv)
			plaintext = self.unpad(decryption_suite.decrypt(ciphertext))
			if plaintext[0] != '1':
				return
			hash = plaintext[1:1+32:]
			request_text = plaintext[33::]
			if sha256(request_text).digest() != hash:
				return

			# decrypt body
			if u'c' in request.POST:
				b64 = str(request.POST['c'])
				padding_len = 4 - (len(b64)%4)
				b64 = b64 + ('=' * padding_len)
				self.log("Decoding %s" % b64)
				payload = urlsafe_b64decode(b64)
				iv = payload[:AES.block_size]
				ciphertext = payload[AES.block_size::]
				decryption_suite = AES.new(sym_key, AES.MODE_CBC, iv)
				plaintext = self.unpad(decryption_suite.decrypt(ciphertext))
				if plaintext[0] != "2":
					return
				hash = plaintext[1:1+32:]
				post = plaintext[33::]
				if sha256(post).digest() != hash:
					return
				key_vals = post.split('&')
				mutable = request.POST._mutable
				request.POST._mutable = True
				for key_val in key_vals:
					key, val = key_val.split('=')
					request.POST[key] = unquote_plus(val)
				request.POST._mutable = mutable

			full_req = request_text + (post if 'c' in request.POST else "")
			self.log("Decrypted request:\n%s" % full_req)
			raw_dec_request = HTTPRequest(request_text)
			request.path_info = raw_dec_request.path
			for header in raw_dec_request.headers:
				normalized_header_name = ('HTTP_' + header.replace('-','_')).upper()
				request.META[normalized_header_name] = raw_dec_request.headers[header]
			request.symmetric_key_ = sym_key
		except:
			return

	def process_response(self, request, response):
		if request.symmetric_key_ is None:
			return response
		new_response = HttpResponse(status = response.status_code)
		b64_key = b64encode(request.symmetric_key_)
		cryptor = AEAD(b64_key)
		b64_aead_output = cryptor.encrypt(response.serialize_headers(), str(response.status_code))
		b64_ct = b64encode(urlsafe_b64decode(b64_aead_output))
		new_response['x-secure-header'] = b64_ct

		b64_aead_output = cryptor.encrypt(str(response.content), "body")
		b64_ct = b64encode(urlsafe_b64decode(b64_aead_output))
		new_response['x-secure-body'] = b64_ct
		return new_response
