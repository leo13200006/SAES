# -*- coding: utf-8 -*-

# -- Sheet --

import sys

sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
w = [None] * 6
 
def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111
 
def int_to_vec(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
 
def vec_to_int(m):
    """Convert a 4-element vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def add_key(s1, s2):
    """Add two keys in GF(2^4)"""  
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub_4_nib_list(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]
     
def shift_row(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]
 
def key_exp(key):
    """Generate the three round keys"""
    def sub_2_nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)

    r_con1, r_con2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ r_con1 ^ sub_2_nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ r_con2 ^ sub_2_nib(w[3])
    w[5] = w[4] ^ w[3]
 
def encrypt(ptext):
    """Encrypt plaintext block"""
    def mix_col(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]    
     
    state = int_to_vec(((w[0] << 8) + w[1]) ^ ptext)
    state = mix_col(shift_row(sub_4_nib_list(sBox, state)))
    state = add_key(int_to_vec((w[2] << 8) + w[3]), state)
    state = shift_row(sub_4_nib_list(sBox, state))
    return vec_to_int(add_key(int_to_vec((w[4] << 8) + w[5]), state))
     
def decrypt(ctext):
    """Decrypt ciphertext block"""
    def i_mix_col(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
     
    state = int_to_vec(((w[4] << 8) + w[5]) ^ ctext)
    state = sub_4_nib_list(sBoxI, shift_row(state))
    state = i_mix_col(add_key(int_to_vec((w[2] << 8) + w[3]), state))
    state = sub_4_nib_list(sBoxI, shift_row(state))
    return vec_to_int(add_key(int_to_vec((w[0] << 8) + w[1]), state))
 
if __name__ == '__main__':
    plaintext = 0b1101011100101000
    key = 0b0100101011110101
    ciphertext = 0b0010010011101100
    key_exp(key)

    try:
        assert encrypt(plaintext) == ciphertext
    except AssertionError:
        print("Encryption error")
        print(encrypt(plaintext), ciphertext)
        sys.exit(1)
    try:
        assert decrypt(ciphertext) == plaintext
    except AssertionError:
        print("Decryption error")
        print(decrypt(ciphertext), plaintext)
        sys.exit(1)
    print("Test ok!")

