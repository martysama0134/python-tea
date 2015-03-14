#! /usr/bin/env python

# Copyright (c) 2013, martysama0134
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# Neither the name of martysama0134 nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""XXTEA Block Cipher Module

Algorithm: http://www.cix.co.uk/~klockstone/xxtea.pdf
See also: http://en.wikipedia.org/wiki/XXTEA

Usage:

	Basically:
	>>> from xxtea import xxtea_encrypt, xxtea_decrypt
	>>> xxtea_testkey = '5EE75350215099170BA771E0CEA40134'.decode('hex')
	>>> a = xxtea_encrypt('abcdefgh', xxtea_testkey)
	>>> xxtea_decrypt(a, xxtea_testkey)
	'abcdefgh'
	
	Entire string process:
	>>> from xxtea import xxtea_encrypt_all, xxtea_decrypt_all
	>>> xxtea_testkey = '5EE75350215099170BA771E0CEA40134'.decode('hex')
	>>> b = xxtea_encrypt_all('*** this is a string ***', xxtea_testkey)
	>>> xxtea_decrypt_all(b, xxtea_testkey)
	'*** this is a string ***'
	
	Class implementation:
	>>> from xxtea import XXTEA
	>>> xxtea_testkey = '5EE75350215099170BA771E0CEA40134'.decode('hex')
	>>> myxxtea = XXTEA(xxtea_testkey)
	>>> myxxtea.decrypt(myxxtea.encrypt('abcdefgh'))
	'abcdefgh'
	
	>>> from xxtea import XXTEA
	>>> xxtea_testkey = '5EE75350215099170BA771E0CEA40134'.decode('hex')
	>>> myxxtea = XXTEA(xxtea_testkey)
	>>> myxxtea.decrypt_all(myxxtea.encrypt_all('*** this is a string ***'))
	'*** this is a string ***'
"""
__author__		= "martysama0134"
__copyright__	= "Copyright (c) 2013 martysama0134"
__date__		= "2013-07-12"
__license__		= "New BSD License"
__url__			= "https://code.google.com/p/python-tea/"
__version__		= "1.8.20130712"

import struct

XXTEA_DELTA = 0x9E3779B9L

def xxtea_encrypt(block, key, endian="!"):
	"""Encrypt multiple of 32 bit data block using XXTEA block cypher
		* block = multiple of 4 bytes (min 64 bit/8 bytes) (byte string)
		* key = 128 bit/16 bytes (byte string)
		* endian = byte order (default '!', commonly used '<' and '>'; see also 'struct' module documentation) (string)
	"""
	(pack, unpack) = (struct.pack, struct.unpack)
	
	global XXTEA_DELTA
	(sum, delta, n) = 0L, XXTEA_DELTA, len(block)/4
	k = unpack(endian+"4L", key)
	v = list(unpack(endian+"%sL"%n, block))
	(z, y) = (v[n-1], v[0])
	
	q = 6+52/n
	for i in xrange(q):
		sum = (sum + delta) & 0xFFFFFFFFL
		e = (sum >> 2&3) & 0xFFFFFFFFL
		p = 0
		while p < n - 1:
			y = v[p+1]
			z = v[p] = (v[p] + (((z>>5)^(y<<2))+((y>>3)^(z<<4))^(sum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFFL
			p += 1
		y = v[0]
		z = v[n-1] = (v[n-1] + (((z>>5)^(y<<2))+((y>>3)^(z<<4))^(sum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFFL
	return pack(endian+"%dL"%n, *v)

def xxtea_decrypt(block, key, endian="!"):
	"""Decrypt multiple of 32 bit data block using XXTEA block cypher
		* block = multiple of 4 bytes (min 64 bit/8 bytes) (byte string)
		* key = 128 bit/16 bytes (byte string)
		* endian = byte order (default '!', commonly used '<' and '>'; see also 'struct' module documentation) (string)
	"""
	(pack, unpack) = (struct.pack, struct.unpack)
	
	global XXTEA_DELTA
	(sum, delta, n) = 0L, XXTEA_DELTA, len(block)/4
	
	k = unpack(endian+"4L", key)
	v = list(unpack(endian+"%dL"%n, block))
	(z, y) = (v[n-1], v[0])
	
	q = 6+52/n
	sum = (q * delta) & 0xFFFFFFFFL
	#while (sum != 0):
	for i in xrange(q):
		e = (sum >> 2&3) & 0xFFFFFFFFL
		p = n-1
		while p > 0:
			z = v[p-1]
			y = v[p] = (v[p] - (((z>>5)^(y<<2))+((y>>3)^(z<<4))^(sum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFFL
			p -= 1
		z = v[n-1]
		y = v[0] = (v[0] - (((z>>5)^(y<<2))+((y>>3)^(z<<4))^(sum^y)+(k[(p&3)^e]^z))) & 0xFFFFFFFFL
		sum = (sum - delta) & 0xFFFFFFFFL
	
	return pack(endian+"%dL"%n, *v)

def xxtea_encrypt_all(data, key, endian="!"):
	"""Encrypt a entire string using XXTEA block cypher"""
	data_s = len(data)
	data_p = data_s%8
	if data_p:
		data_pl = 8-data_p
		data+=(data_pl*chr(0))
		data_s+=data_pl
	return xxtea_encrypt(data, key, endian)

def xxtea_decrypt_all(data, key, endian="!"):
	"""Decrypt a entire string using XXTEA block cypher"""
	data_s = len(data)
	data_p = data_s%8
	if data_p:
		data_pl = 8-data_p
		data+=(data_pl*chr(0))
		data_s+=data_pl
	return xxtea_decrypt(data, key, endian)

class XXTEA(object):
	"""XXTEA class implementation"""
	def __init__(self, key, endian="!"):
		self.key = key
		self.endian = endian

	def encrypt(self, block):
		global xxtea_encrypt
		return xxtea_encrypt(block, self.key, self.endian)

	def decrypt(self, block):
		global xxtea_decrypt
		return xxtea_decrypt(block, self.key, self.endian)

	def encrypt_all(self, data):
		global xxtea_encrypt_all
		return xxtea_encrypt_all(data, self.key, self.endian)

	def decrypt_all(self, data):
		global xxtea_decrypt_all
		return xxtea_decrypt_all(data, self.key, self.endian)

if __name__ == "__main__":
	def Usage():
		print '''Usage:
	xxtea.py -f "file" -k "5EE75350215099170BA771E0CEA40134" -d
	xxtea.py -f "file" -k "5EE75350215099170BA771E0CEA40134" -e
'''
	import getopt
	import os
	import sys
	try:
		optlist, args = getopt.getopt(sys.argv[1:],"f:k:ed",('file=','key=','encrypt','decrypt'))
		
		t_file, t_fname = None, ""
		t_key = None
		t_mode = 0
		for o, a in optlist:
			if o in ('-f', '--file'):
				if not os.path.exists(a):
					sys.exit("File %s not found" % a)
				try:
					t_fname = a
					t_file = open(t_fname, "rb").read()
				except IOError:
					sys.exit("File %s cannot be opened" % a)
			elif o in ('-k', '--key'):
				if len(a)!=(16*2):
					sys.exit("Incorrect key length %s" % a)
				t_key = a.decode("hex")
			elif o in ('-e', '--encrypt'):
				t_mode = 1
			elif o in ('-d', '--decrypt'):
				t_mode = 2
		if (not t_file) or (not t_key) or (not t_mode):
			Usage()
			sys.exit(2)
		t_xxtea = XXTEA(t_key)
		t_res = None
		suffix = ""
		if t_mode==1:
			suffix = "enc.xxtea"
			t_res = t_xxtea.encrypt_all(t_file)
		elif t_mode==2:
			suffix = "dec.xxtea"
			t_res = t_xxtea.decrypt_all(t_file)
		if not t_res:
			sys.exit("Failed to encrypt/decrypt %d" % t_fname)
		t_f1 = open("%s.%s"%(t_fname, suffix), "wb")
		t_f1.write(t_res)
		t_f1.close()
	except getopt.GetoptError, err:
		sys.exit(err)










