import sys

sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
w = [None] * 6
 
def mult(p1, p2):
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
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            
 
def vec_to_int(m):
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def add_key(s1, s2):
    """Add two keys in GF(2^4)"""  
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub_4_nib_list(sbox, s):
    return [sbox[e] for e in s]
     
def shift_row(s):
    return [s[0], s[1], s[3], s[2]]
 
def key_exp(key):
    def sub_2_nib(b):
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)

    r_con1, r_con2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ r_con1 ^ sub_2_nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ r_con2 ^ sub_2_nib(w[3])
    w[5] = w[4] ^ w[3]
 
def encrypt(ptext):
    def mix_col(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]    
     
    state = int_to_vec(((w[0] << 8) + w[1]) ^ ptext)
    state = mix_col(shift_row(sub_4_nib_list(sBox, state)))
    state = add_key(int_to_vec((w[2] << 8) + w[3]), state)
    state = shift_row(sub_4_nib_list(sBox, state))
    return vec_to_int(add_key(int_to_vec((w[4] << 8) + w[5]), state))
     
def decrypt(ctext):
    def i_mix_col(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
     
    state = int_to_vec(((w[4] << 8) + w[5]) ^ ctext)
    state = sub_4_nib_list(sBoxI, shift_row(state))
    state = i_mix_col(add_key(int_to_vec((w[2] << 8) + w[3]), state))
    state = sub_4_nib_list(sBoxI, shift_row(state))
    return vec_to_int(add_key(int_to_vec((w[0] << 8) + w[1]), state))
 

pt = 0b1101011100101000
key = 0b0100101011110101
key_exp(key)

ct = encrypt(pt)
print("Encrypted message ", ct)
dt = decrypt(ct)
print("Decrypt message ", dt)
