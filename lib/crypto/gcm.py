#!/usr/bin/env python

from aes import *
from struct import *
import binascii, struct

def xor_strings(xs, ys):
	y = [xs[j] ^ ys[j] for j in range(len(xs))]
	return struct.pack('B' * len(y), *y)

def gcm_rightshift(vec):
    for x in range(15, 0, -1):
        c = vec[x] >> 1
        c |= (vec[x-1] << 7) & 0x80
        vec[x] = c
    vec[0] >>= 1
    return vec

def gcm_gf_mult(a, b):
    mask = [ 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 ]
    poly = [ 0x00, 0xe1 ]

    Z = [0] * 16
    V = [c for c in a]

    for x in range(128):
        if b[x >> 3] & mask[x & 7]:
            Z = [V[y] ^ Z[y] for y in range(16)]
        bit = V[15] & 1
        V = gcm_rightshift(V)
        V[0] ^= poly[bit]
    return Z

def ghash(h, auth_data, data):
    u = (16 - len(data)) % 16
    v = (16 - len(auth_data)) % 16
    
    x = auth_data
    x += bytes.fromhex('00'*v)
    if data != '':
    	x += data
    x += bytes.fromhex('00'*u)
    x += pack('>QQ', len(auth_data) * 8, len(data) * 8)

    y = [0] * 16
    vec_h = h

    for i in range(0, len(x), 16):
        block = x[i:i+16]
        y = [y[j] ^ block[j] for j in range(16)]
        y = gcm_gf_mult(y, vec_h)

    return struct.pack('B' * len(y), *y)

def inc32(block):
    counter, = unpack('>L', block[12:])
    counter += 1
    return block[:12] + pack('>L', counter)

def gctr(cipher, expandedKey, nbrRounds, icb, plaintext):
    y = bytes()
    if len(plaintext) == 0:
        return y
    
    cb = icb
    
    for i in range(0, len(plaintext), 16):
        cb = inc32(cb)
        encrypted = cipher.encrypt(cb, expandedKey, nbrRounds)
        encrypted = struct.pack('B' * len(encrypted), *encrypted)
        plaintext_block = plaintext[i:i+16]
        y += xor_strings(plaintext_block, encrypted[:len(plaintext_block)])
    
    return y

def gcm_decrypt(key, iv, encrypted, auth_data, tag):
    
    aes = AES()
    keysize = len(key)
    (nbrRounds, expandedKey) = aes.KeyExpand(key, keysize)
    
    h = aes.encrypt([0] * 16, expandedKey, nbrRounds)

    if len(iv) == 12:
        y0 = iv + bytes.fromhex('00 00 00 01')
    else:
        y0 = ghash(h, bytes(), iv)
    
    decrypted = gctr(aes, expandedKey, nbrRounds, y0, encrypted)
    s = ghash(h, auth_data, encrypted)

    t = aes.encrypt(y0, expandedKey, nbrRounds)
    t = struct.pack('B' * len(t), *t)
    
    T = xor_strings(s, t)
    if T != tag:
        raise ValueError('Decrypted data is invalid')
    else:
        return decrypted

def gcm_encrypt(key, iv, plaintext, auth_data):
    
    aes = AES()
    keysize = len(key)
    (nbrRounds, expandedKey) = aes.KeyExpand(key, keysize)
    
    h = aes.encrypt([0] * 16, expandedKey, nbrRounds)
    
    if len(iv) == 12:
        y0 = iv + bytes.fromhex('00 00 00 01')
    else:
        y0 = ghash(h, bytes(), iv)
    
    encrypted = gctr(aes, expandedKey, nbrRounds, y0, plaintext)
    s = ghash(h, auth_data, encrypted)
    t = aes.encrypt(y0, expandedKey, nbrRounds)
    t = struct.pack('B' * len(t), *t)
    
    T = xor_strings(s, t)
    return (encrypted, T)

def main():

    print ("see http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf")
    k = binascii.unhexlify('AD7A2BD03EAC835A6F620FDCB506B345')
    p = binascii.unhexlify('')
    a = binascii.unhexlify('D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001')
    iv = binascii.unhexlify('12153524C0895E81B2C28465')
    c, t = gcm_encrypt(k, iv, p, a)
    print ('c:', binascii.hexlify(c).decode('utf-8'), 't:', binascii.hexlify(t).decode('utf-8'))
    assert c == binascii.unhexlify('')
    assert t == binascii.unhexlify('F09478A9B09007D06F46E9B6A1DA25DD')
        
    k = binascii.unhexlify('E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72')
    p = binascii.unhexlify('')
    a = binascii.unhexlify('D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001')
    iv = binascii.unhexlify('12153524C0895E81B2C28465')
    c, t = gcm_encrypt(k, iv, p, a)
    print ('c:', binascii.hexlify(c).decode('utf-8'), 't:', binascii.hexlify(t).decode('utf-8'))
    assert c == binascii.unhexlify('')
    assert t == binascii.unhexlify('2F0BC5AF409E06D609EA8B7D0FA5EA50')
        
    k = binascii.unhexlify('AD7A2BD03EAC835A6F620FDCB506B345')
    p = binascii.unhexlify('08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002')
    a = binascii.unhexlify('D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81')
    iv = binascii.unhexlify('12153524C0895E81B2C28465')
    c, t = gcm_encrypt(k, iv, p, a)
    print ('c:', binascii.hexlify(c).decode('utf-8'), 't:', binascii.hexlify(t).decode('utf-8'))
    assert c == binascii.unhexlify('701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D')
    assert t == binascii.unhexlify('4F8D55E7D3F06FD5A13C0C29B9D5B880')
        
    assert p == gcm_decrypt(k, iv, c, a, t)

if __name__ == '__main__':
    main()