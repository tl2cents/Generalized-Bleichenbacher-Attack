import cryptography.hazmat.primitives.asymmetric.rsa as rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import binascii
import math
import textwrap
from Crypto.Util.number import *

# modified form https://gist.github.com/kazkansouh/e4d710c6a6928187323fa164bdd70401

def local_setup(oracle_prfix="0011111111", choose_plaintext=b"flag{this_is_a_sample_flag_for_testing!}"):
    print('Using local loop back oracle for testing')
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()
    pn = pub_key.public_numbers()
    ciphertext = pow(int.from_bytes(choose_plaintext, "big"), pn.e, pn.n)
    
    if verbose:
        print('  keysize: {}'.format(priv_key.key_size))
        print('  e: {}'.format(pn.e))
        print('  n: {}'.format(pn.n))
        print('  p: {}'.format(priv_key.private_numbers().p))
        print('  q: {}'.format(priv_key.private_numbers().q))
        print('  d: {}'.format(priv_key.private_numbers().d))

        print('  c: {}'.format(hex(ciphertext)))
        print()
    
    if oracle_prfix == "pkcs1.5":
        prefix_nbits = 16
        prefix_num = 0x0002
    else:
        prefix_nbits = len(oracle_prfix)
        prefix_num = int(oracle_prfix, 2)

    def oracle(ct):
        if type(ct) == int:
            c = ct
        elif type(ct) == bytes:
            c = int.from_bytes(ct, 'big')
        elif type(ct) == str:
            c = int(ct, 16)
        else:
            print("Kidding?")
            return None

        d = priv_key.private_numbers().d
        m = pow(c, d, pn.n)
        padding_pos = pn.n.bit_length() - prefix_nbits
        return (m >> padding_pos) == prefix_num

    def _oracle(ct):
        c = int.from_bytes(ct, 'big')

        try:
            priv_key.decrypt(
                ct,
                padding.PKCS1v15()
            )
            return True
        except ValueError:
            return False

    return ciphertext, oracle, pn.e, pn.n

# these two defs avoid rounding issues with floating point during
# division (especially with large numbers)


def ceildiv(a, b):
    return -(-a // b)


def floordiv(a, b):
    return (a // b)

def pad_message(prefix, nbytes, m):
    prefix_len = len(prefix)
    prefix_num = int(prefix,2)
    return (int.from_bytes(m, "big") + (prefix_num << (nbytes * 8 - prefix_len))).to_bytes(nbytes,"big")


oracle_ctr = 0
verbose = False
def rsa_prefix_padding_oracle_attack(n, e, ct, padding_prefix, oracle):
    print('Generalized Bleichenbacher RSA Padding Oracle Attack')
    print('  for more info see 1998 paper.')
    print()

    # byte length of n
    k = int(ceildiv(math.log(n, 2), 8))
    c = ct

    # lift oracle defition to take integers
    def oracle_int(x):
        global oracle_ctr
        oracle_ctr = oracle_ctr + 1
        if oracle_ctr % 100000 == 0:
            print("[{}K tries] ".format(oracle_ctr // 1000), end='', flush=True)
        return oracle(x)
    
    prefix_nbits = len(padding_prefix)
    prefix_num = int(padding_prefix, 2)
    nbits = n.bit_length()
    B = pow(2, nbits - prefix_nbits)

    # precompute constants
    _lB = prefix_num * B
    _uB = (prefix_num + 1) * B
    padding_pos = nbits - prefix_nbits
    if verbose:
        print("[+] Testing the strict bounds, valid bounds should output : ttff")
        print((_lB >> padding_pos) == prefix_num)
        print(((_uB - 1) >> padding_pos) == prefix_num)
        print((_lB-1 >> padding_pos) == prefix_num)
        print(((_uB) >> padding_pos) == prefix_num)

    def multiply(x, y): return (x * pow(y, e, n)) % n

    # should be identity as c is valid cipher text
    c0 = multiply(c, 1)
    assert c0 == c
    i = 1
    M = [(_lB, _uB - 1)]
    s = 1

    # const_s : to enlarge the plaintext if the plaintext is too short
    const_s = None
    # ensure everything is working as expected
    if oracle_int(c0):
        # plaintext is padded correctly
        print('Oracle ok, implicit step 1 passed')
    else:
        # plaintext is not padded and might be too short
        const_s = 2**(nbits - prefix_nbits)
        c0 = multiply(c0, const_s)
        s = 1
        while not oracle_int(multiply(c0, s)):
            s += 1
        c0 = multiply(c0, s)
        assert oracle_int(c0)
        const_s *= s
        print(f"Ciphertext of unpadded message: case 1 done {s} times")

    while True:
        if i == 1:
            if verbose: print('start case 2.a: ', end='', flush=True)
            ss = ceildiv(n, _uB)
            while not oracle_int(multiply(c0, ss)):
                ss = ss + 1
            if verbose: print('done. found s1 in {} iterations: {}'.format(
                ss - ceildiv(n, _uB), ss))
        else:
            assert i > 1
            if len(M) > 1:
                if verbose: print('start case 2.b: ', end='', flush=True)
                ss = s + 1
                while not oracle_int(multiply(c0, ss)):
                    ss = ss + 1
                if verbose : print('done. found s{} in {} iterations: {}'.format(
                    i, ss-s, ss))
            else:
                if verbose: print('start case 2.c: ', end='', flush=True)
                assert len(M) == 1
                a, b = M[0]
                r = ceildiv(2 * (b * s - _lB), n)
                ctr = 0
                while True:
                    # note: the floor function below needed +1 added
                    # to it, this is not clear from the paper (see
                    # equation 2 in paper where \lt is used instead of
                    # \lte).
                    for ss in range(
                            ceildiv(_lB + r * n, b),
                            floordiv(_uB + r * n, a) + 1):
                        ctr = ctr + 1
                        if oracle_int(multiply(c0, ss)):
                            break
                    else:
                        r = r + 1
                        continue
                    break
                if verbose: print('done. found s{} in {} iterations: {}'.format(i, ctr, ss))
        # step 3, narrowing solutions
        MM = []
        for a, b in M:
            for r in range(ceildiv(a * ss - _uB + 1, n),
                           floordiv(b * ss - _lB, n) + 1):
                m = (
                    max(a, ceildiv(_lB + r * n, ss)),
                    min(b, floordiv(_uB - 1 + r * n, ss))
                )
                if m not in MM:
                    MM.append(m)
                    if verbose: print('found interval [{},{}]'.format(m[0], m[1]))
        # step 4, compute solutions
        M = MM
        s = ss
        i = i + 1
        if len(M) == 1 and M[0][0] == M[0][1]:
            print()
            print('Completed!')
            print('used the oracle {} times'.format(oracle_ctr))
            # note, no need to find multiplicative inverse of s0 in n
            # as s0 = 1, so M[0][0] is directly the message.
            if const_s != None:
                message = (M[0][0]*inverse(const_s, n) % n)
            else:
                message = M[0][0]
            m_len = (message.bit_length()-1)//8 + 1
            print("[+] decrypted message : ", message.to_bytes(m_len, 'big'))
            print('raw decryption in hex format: {}'.format(
                hex(message)))
            return
        
if __name__ == "__main__":
    # note : if the prefix is too long, time cost may be intolerable
    # padded bersion
    # oracle_prfix = bin(11451)[2:].zfill(16)
    # choose_plaintext = pad_message(oracle_prfix , 1024//8 , b"flag{this_is_a_sample_flag_for_testing!}")
    
    # unpadded bersion
    oracle_prfix = bin(1145)[2:].zfill(11)
    print(f"[+] Try the prefix {oracle_prfix = }")
    choose_plaintext = b"flag{this_is_a_sample_flag_for_testing!}"
    ciphertext, oracle, e, n = local_setup(oracle_prfix,choose_plaintext)
    rsa_prefix_padding_oracle_attack(n,e,ciphertext,oracle_prfix,oracle)