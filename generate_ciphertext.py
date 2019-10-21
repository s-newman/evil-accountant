#!/usr/bin/env python3

from Crypto.Cipher import AES

import base64

FLAG = 'RITSEC{this_is_the_flag_lol_hii}'
key = bytes([43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60])

cipher = AES.new(key, AES.MODE_ECB)
msg = cipher.encrypt(FLAG)
print(base64.b64encode(msg).decode())
