import random
from base64 import b64encode
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

class IntegrityGuard:
	def __init__(self):
		self.log_file = open('/home/django/error.log','a')

		with open('/home/django/private_key','r') as f:
			priv_key = f.read()
		priv_key_obj = RSA.importKey(priv_key)

		with open('/home/django/public_key','r') as f:
			pub_key = f.read()
		pub_key_obj = RSA.importKey(pub_key)

		self.signer = PKCS1_v1_5.new(priv_key_obj)
		self.verifier = PKCS1_v1_5.new(pub_key_obj)

	def log(self, msg):
		self.log_file.write("[LOG]: " + msg + '\n')
		self.log_file.flush()

	def sign(self, message):
		digest = MD5.new()
		digest.update(message)
		signature = self.signer.sign(digest)
		assert self.verifier.verify(digest, signature)
		return b64encode(signature)

	def get_signature(self, response, protected_headers):
		# canonicalize order of headers
		protected_headers.sort()

		# form canonical representation of headers
		header_vals = []
		for header in protected_headers:
			header_val_str = '%s: %s' % (header.lower(), response[header])
			header_vals.append(header_val_str)
		canonical_headers = '\r\n'.join(header_vals)

		# compute signature of full canonical form
		canonical_repr = "%s\r\n%s\r\n\r\n%s" % (response.status_code, canonical_headers, response.content)
		self.log(canonical_repr.encode('hex'))
		return self.sign(canonical_repr)

	def process_response(self, request, response):
		fields = {}
		protected_headers = []

		# tuple of headers that we might wanna protect
		for header in ('Content-Type','Location'):
			if header in response:
				protected_headers.append(header)

		# compile all the protected headers
		if protected_headers:
			protected_headers_string = ','.join(protected_headers)
			fields['h'] = protected_headers_string

		# compute the overall signature
		fields['sig'] = self.get_signature(response, protected_headers)

		# compile all the key-value pairs into a header
		key_values = []
		for k in fields:
			key_values.append('%s=%s' % (k, fields[k]))
		signature = '; '.join(key_values)
		response['X-Signature'] = signature

		# randomly inject a mutation to simulate MITM tampering
		if random.randint(1,10) == 5:
			response.content += '<--- this resource has been mutated! --->'

		return response
