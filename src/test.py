import unittest
from src.SHA512 import SHA512


class TestSHA512(unittest.TestCase):
    def setUp(self):
        self.f = SHA512

    def test_1(self):
        self.assertEqual(self.f('').print(),
                         'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
                         '47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')

    def test_2(self):
        self.assertEqual(self.f('a').print(),
                         '1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53' +
                         '02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75')

    def test_3(self):
        self.assertEqual(self.f('abc').print(),
                         'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
                         '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')

    def test_4(self):
        self.assertEqual(self.f('message digest').print(),
                         '107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33' +
                         '09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c')

    def test_5(self):
        self.assertEqual(self.f('abcdefghijklmnopqrstuvwxyz').print(),
                         '4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429' +
                         '955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1')

    def test_6(self):
        self.assertEqual(self.f('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').print(),
                         '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335' +
                         '96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445')

    def test_7(self):
        self.assertEqual(self.f('A...Za...z0...9').print(),
                         '102a952546d1d765b20d23f9a8240ff790dc07348bf68c7972e6fbd8d23df945' +
                         '0cfeffa9dc14cb64a9cb5eccd2fd4265ec47eae2c61f9081b89acd8f8e0b669f')

    def test_8(self):
        self.assertEqual(self.f('1234567890' * 8).print(),
                         '72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a' +
                         '2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843')


if __name__ == '__main__':
    sha512_suite = unittest.TestLoader().loadTestsFromTestCase(TestSHA512)

    tests = unittest.TestSuite([sha512_suite])

    unittest.TextTestRunner(verbosity=2).run(tests)
