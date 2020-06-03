from src.SHA512 import SHA512

if __name__ == '__main__':
    message = 'BDAN is the best subject and we love it'

    print('Message to hash:', message)
    print('Hashed message:', SHA512(message))
