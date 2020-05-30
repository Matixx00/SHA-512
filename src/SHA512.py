# List of useful links:
#
# Secure Hash Standard
# https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
#
# C++ implementation
# http://www.zedwood.com/article/cpp-sha512-function
#
# C implementation
# https://akkadia.org/drepper/SHA-crypt.txt
#
# JavaScript implementation
# http://www.movable-type.co.uk/scripts/sha512.html
#
# Python implementation
# https://github.com/thomdixon/pysha2/blob/master/sha2/sha512.py

import math


class SHA512(object):
    """
    Maybe its not the fastest implementation of SHA512 hash algorithm but it works.
    We were trying to make it without using libraries like Ctypes - just clear python
    (that 'import math' doesnt look good :( ).
    """
    # message to hash
    string = ""

    def __init__(self, string):
        self.string = string
        self.hash()

    # number of rounds
    N = 0

    # preprocessed message before padded it
    value = 0

    # SHA-512 logical functions

    def rot(self, x, n):
        """Cyclic rotation.

        :param x: 64-bit word
        :param n: Number of bits
        """
        return (x >> n) | (x << (64 - n))

    def ch(self, x, y, z):
        """Choice function."""
        return (x & y) ^ (~x & z)

    def maj(self, x, y, z):
        """Majority function."""
        return (x & y) ^ (x & z) ^ (y & z)

    def f1(self, x):
        return self.rot(x, 28) ^ self.rot(x, 34) ^ self.rot(x, 39)

    def f2(self, x):
        return self.rot(x, 14) ^ self.rot(x, 18) ^ self.rot(x, 41)

    def f3(self, x):
        return self.rot(x, 1) ^ self.rot(x, 8) ^ (x >> 7)

    def f4(self, x):
        return self.rot(x, 19) ^ self.rot(x, 61) ^ (x >> 6)

    """
    methods for adding with modulo.
    Python does not support function overloading, so we had to make different def names
    """
    def add2(self, a, b):
        return (a + b) % 18446744073709551616  # 2^64

    def add3(self, a, b, c):
        return (self.add2(a, b) + c) % 18446744073709551616  # 2^64

    def add4(self, a, b, c, d):
        return (self.add3(a, b, c) + d) % 18446744073709551616  # 2^64

    def add5(self, a, b, c, d, e):
        return (self.add4(a, b, c, d) + e) % 18446744073709551616  # 2^64

    # Eighty constant 64-bit words
    # Fun fact:
    # These words represent the first 64 bits of the fractional parts of
    # the cube roots of the first 80 prime numbers.
    # For SHA-384 and SHA-512 these words are the same. For SHA-256 is used
    # first 32 bits of first 64 prime numbers.
    K = (0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
         0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
         0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
         0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
         0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
         0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
         0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
         0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
         0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
         0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
         0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
         0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
         0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
         0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
         0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
         0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
         0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
         0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
         0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
         0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817)

    H = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]


    def count_value(self):
        """
        Preprocess before hash computation as it is in documentation
        (value_of_message + 1 + k * 0_bits + 128bit_length_of_message)
        :return: assign self.value to counted value
        """
        binary = bytes(0)

        for char in self.string:
            binary = binary + ord(char).to_bytes(length=1, byteorder='big')
        value = int.from_bytes(binary, byteorder='big')
        # shift before we add 1000 to make it right
        value = value << 4
        # in binary 1000 - we need that 1(from documentation)
        value = value + 8
        # 1024 - sum, 8 * each char in string, 4 - we added 4 bits above
        value = value << (1024 * self.N - 8 * len(self.string) - 4)
        # length of string at the end
        value = value + 8 * len(self.string)
        self.value = value

    def getw(self, N):
        """
        :param N: Number of round
        :return: Array of padded message (see documentation)
        """
        # shifting value as it is necessary for current round N
        value = self.value >> 1024 * (self.N - N)
        W = []
        # creating empty array
        for i in range(80):
            W.append(0)
        i = 15  # for loop
        # make first 16 values
        while i > 0:
            W[i] = int(bin(value)[-64:], 2)
            value = value >> 64  # shift to stick out bits for next iteration
            i = i - 1
        # assign here first part to avoid situation when value starts by 0
        W[0] = value
        # make values 16-80 as it is in documentation
        for t in range(16, 80):
            W[t] = self.add4(self.f4(W[t - 2]), W[t - 7], self.f3(W[t - 15]), W[t - 16])
        return W

    def one_round(self, w):
        """
        This is one round of SHA512 algorithm
        :param w: array of padded message
        :return: assigning hashed values to H array
        """
        a = self.H[0]
        b = self.H[1]
        c = self.H[2]
        d = self.H[3]
        e = self.H[4]
        f = self.H[5]
        g = self.H[6]
        h = self.H[7]

        for t in range(0, 80):
            t1 = self.add5(h, self.f2(e), self.ch(e, f, g), self.K[t], w[t])
            t2 = self.add2(self.f1(a), self.maj(a, b, c))
            h = g
            g = f
            f = e
            e = self.add2(d, t1)
            d = c
            c = b
            b = a
            a = self.add2(t1, t2)

        self.H[0] = self.add2(a, self.H[0])
        self.H[1] = self.add2(b, self.H[1])
        self.H[2] = self.add2(c, self.H[2])
        self.H[3] = self.add2(d, self.H[3])
        self.H[4] = self.add2(e, self.H[4])
        self.H[5] = self.add2(f, self.H[5])
        self.H[6] = self.add2(g, self.H[6])
        self.H[7] = self.add2(h, self.H[7])

    def hash(self):
        # count number of needed blocks.
        # 111 - max number of chars in one round.
        # 128 - number of chars which we can put in 1024 bits block.
        # +1 - to make number of rounds > 0
        self.N = int(math.ceil((len(self.string) - 111) / 128)) + 1
        self.count_value()
        for N in range(1, self.N+1):
            self.one_round(self.getw(N))
        out = ""
        for i in self.H:
            out = out + hex(i)[2:] + " "
        print(out)
