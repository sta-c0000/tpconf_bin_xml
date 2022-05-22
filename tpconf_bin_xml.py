#!/usr/bin/env python3

# Copyright 2018 Alain Ducharme
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Description:
# Command line utility to convert TP-Link router backup config files:
#   - conf.bin => decrypt, md5hash and uncompress => conf.xml
#   - conf.xml => compress, md5hash and encrypt   => conf.bin

import argparse
from hashlib import md5
from os import path
import re
from struct import pack, pack_into, unpack_from

from Cryptodome.Cipher import DES # apt install python3-pycryptodome (OR: pip install pycryptodomex)

__version__ = '0.2.9'

def compress(src, skiphits=False):
    '''Compress buffer'''
    # Make sure last byte is NULL
    if src[-1]:
        src += b'\0'
    size = len(src)
    buffer_countdown = size
    hash_table = [0] * 0x2000
    dst = bytearray(0x8000)   # max compressed buffer size
    block16_countdown = 0x10  # 16 byte blocks
    block16_dict_bits = 0     # bits for dictionnary bytes

    def put_bit(bit):
        nonlocal block16_countdown, block16_dict_bits, d_p, d_pb
        if block16_countdown:
            block16_countdown -= 1
        else:
            pack_into('H', dst, d_pb, block16_dict_bits)
            d_pb = d_p
            d_p += 2
            block16_countdown = 0xF
        block16_dict_bits = (bit + (block16_dict_bits << 1)) & 0xFFFF

    def put_dict_ld(bits):
        ldb = bits >> 1
        while True:
            lb = (ldb - 1) & ldb
            if not lb:
                break
            ldb = lb
        put_bit(int(ldb & bits > 0))
        ldb = ldb >> 1
        while ldb:
            put_bit(1)
            put_bit(int(ldb & bits > 0))
            ldb = ldb >> 1
        put_bit(0)

    def hash_key(offset):
        b4 = src[offset:offset+4]
        hk = 0
        for b in b4[:3]:
            hk = (hk + b) * 0x13d
        return ((hk + b4[3]) & 0x1FFF)

    pack_into(packint, dst, 0, size)    # Store original size
    dst[4] = src[0]                     # Copy first byte
    buffer_countdown -= 1
    s_p = 1
    s_ph = 0
    d_pb = 5
    d_p = 7

    while buffer_countdown > 4:
        while s_ph < s_p:
            hash_table[hash_key(s_ph)] = s_ph
            s_ph += 1
        hit = hash_table[hash_key(s_p)]
        count = 0
        if hit:
            while True:
                if src[hit + count] != src[s_p + count]:
                    break
                count += 1
                if count == buffer_countdown:
                    break
            if count >= 4 or count == buffer_countdown:
                hit = s_p - hit - 1
                put_bit(1)
                put_dict_ld(count - 2)
                put_dict_ld((hit >> 8) + 2)
                dst[d_p] = hit & 0xFF
                d_p += 1
                buffer_countdown -= count
                s_p += count
                if skiphits:
                    hash_table[hash_key(s_ph)] = s_ph
                    s_ph += count
                continue
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1
    while buffer_countdown:
        put_bit(0)
        dst[d_p] = src[s_p]
        s_p += 1
        d_p += 1
        buffer_countdown -= 1
    pack_into('H', dst, d_pb, (block16_dict_bits << block16_countdown) & 0xFFFF)
    return d_p, dst[:d_p]    # size, compressed buffer

def uncompress(src):
    '''Uncompress buffer'''
    block16_countdown = 0 # 16 byte blocks
    block16_dict_bits = 0 # bits for dictionnary bytes

    def get_bit():
        nonlocal block16_countdown, block16_dict_bits, s_p
        if block16_countdown:
            block16_countdown -= 1
        else:
            block16_dict_bits = unpack_from('H', src, s_p)[0]
            s_p += 2
            block16_countdown = 0xF
        block16_dict_bits = block16_dict_bits << 1
        return 1 if block16_dict_bits & 0x10000 else 0 # went past bit

    def get_dict_ld():
        bits = 1
        while True:
            bits = (bits << 1) + get_bit()
            if not get_bit():
                break
        return bits

    size = unpack_from(packint, src, 0)[0]
    dst = bytearray(size)
    s_p = 4
    d_p = 0

    dst[d_p] = src[s_p]
    s_p += 1
    d_p += 1
    while d_p < size:
        if get_bit():
            num_chars = get_dict_ld() + 2
            msB = (get_dict_ld() - 2) << 8
            lsB = src[s_p]
            s_p += 1
            offset = d_p - (lsB + 1 + msB)
            for i in range(num_chars):
                # 1 by 1 ∵ sometimes copying previously copied byte
                dst[d_p] = dst[offset]
                d_p += 1
                offset += 1
        else:
            dst[d_p] = src[s_p]
            s_p += 1
            d_p += 1
    return dst

def verify(src):
    # Try md5 hash excluding up to last 8 (padding) bytes
    if not any(src[:16] == md5(src[16:len(src)-i]).digest() for i in range(8)):
        print('ERROR: Bad file or could not decrypt file - MD5 hash check failed!')
        exit()

def verify_ac1350(src):
    length = unpack_from(packint, src, 16)[0]
    payload = src[20:][:length]
    if src[:16] != md5(payload).digest():
        print('ERROR: Bad file or could not decrypt file - MD5 hash check failed!')
        exit()
    return payload

def check_size_endianness(src):
    global packint
    if unpack_from(packint, src)[0] > 0x20000:
        packint = '<I' if packint == '>I' else '>I'
        if unpack_from(packint, src)[0] > 0x20000:
            print('ERROR: compressed size too large for a TP-Link config file!')
            exit()
        print('WARNING: wrong endianness, automatically switching. (see -h)')
    endianness = 'little' if packint == '<I' else 'big'
    print(f'OK: appears your device uses {endianness}-endian.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TP-Link router config file processor.')
    parser.add_argument('infile', help='input file (e.g. conf.bin or conf.xml)')
    parser.add_argument('outfile', help='output file (e.g. conf.bin or conf.xml)')
    parser.add_argument('-l', '--littleendian', action='store_true',
                        help='Use little-endian (default: big-endian)')
    parser.add_argument('-n', '--newline', action='store_true',
                        help='Replace EOF NULL with newline (after uncompress)')
    parser.add_argument('-o', '--overwrite', action='store_true',
                        help='Overwrite output file')
    args = parser.parse_args()

    if path.getsize(args.infile) > 0x20000:
        print('ERROR: Input file too large for a TP-Link config file!')
        exit()
    if not args.overwrite and path.exists(args.outfile):
        print('ERROR: Output file exists, use -o to overwrite')
        exit()

    packint = '<I' if args.littleendian else '>I'

    key = b'\x47\x8D\xA5\x0B\xF9\xE3\xD2\xCF'
    crypto = DES.new(key, DES.MODE_ECB)

    with open(args.infile, 'rb') as f:
        src = f.read()

    if src.startswith(b'<?xml'):
        if b'1350 v' in src: # AC1350 (Archer C60) and ISP variants
            print('OK: AC1350 XML file - compressing, hashing and encrypting…')
            size, dst = compress(src, True)
            md5hash = md5(dst[:size]).digest()
            dst = md5hash + pack(packint, size) + bytes(dst)
        elif b'W9980' in src or b'W8980' in src:
            print('OK: W9980/W8980 XML file - hashing, compressing and encrypting…')
            md5hash = md5(src).digest()
            size, dst = compress(md5hash + src)
        elif b'W8970' in src:
            print('OK: W8970 XML file - hashing and encrypting…')
            # Make sure last byte is NULL
            if src[-1]:
                src += b'\0'
            md5hash = md5(src).digest()
            dst = md5hash + src
        else:
            skiphits = False
            if b'Archer' in src:
                if packint == '>I': # Archer models can be little or big-endian!
                    print('WARNING: make sure you are using correct endianness. (see -h)')
                # Older Archer C2 & C20 v1 skiphits, newer v4 & v5 don't
                if re.search(b'Archer C2[0-9]?[A-z]? v1', src):
                    skiphits = True
            print('OK: XML file - compressing, hashing and encrypting…')
            size, dst = compress(src, skiphits)
            md5hash = md5(dst[:size]).digest()
            dst = md5hash + bytes(dst)

        # data length for encryption must be multiple of 8
        if len(dst) & 7:
            dst += b'\0' * (8 - (len(dst) & 7))
        output = crypto.encrypt(bytes(dst))

    else:
        xml = None
        # Assuming encrypted config file
        if len(src) & 7: # Encrypted file length must be multiple of 8
            print('ERROR: Wrong input file type!')
            exit()
        src = crypto.decrypt(src)
        if src[16:21] == b'<?xml':  # XML (not compressed?)
            verify(src)
            print('OK: BIN file decrypted, MD5 hash verified…')
            xml = src[16:]
        elif src[20:27] == b'<\0\0?xml':  # compressed XML (W9970)
            verify(src)
            src = src[16:]
            check_size_endianness(src)
            print('OK: BIN file decrypted, MD5 hash verified, uncompressing…')
            xml = uncompress(src)
        elif src[22:29] == b'<\0\0?xml':  # compressed XML (W9980/W8980)
            check_size_endianness(src)
            print('OK: BIN file decrypted, uncompressing…')
            dst = uncompress(src)
            verify(dst)
            print('OK: MD5 hash verified')
            xml = dst[16:]
        elif src[24:31] == b'<\0\0?xml':  # compressed XML (AC1350)
            '''
            payload md5 (16b) | payload size (4b) | payload
            '''
            check_size_endianness(src[16:])
            src = verify_ac1350(src)
            print('OK: BIN file decrypted, MD5 hash verified, uncompressing…')
            xml = uncompress(src)
        else:
            print('ERROR: Unrecognized file type!')
            exit()

        if args.newline:
            if xml[-1] == 0:    # NULL
                xml[-1] = 0xa   # LF
        output = xml

    with open(args.outfile, 'wb') as f:
        f.write(output)
    print('Done.')
