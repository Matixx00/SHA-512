from src.SHA512 import SHA512

if __name__ == '__main__':
    # 01100001 01100010 01100011
    #    a         b       c
    a = 1000000 * "a"
    print(a)
    print(SHA512(a))

