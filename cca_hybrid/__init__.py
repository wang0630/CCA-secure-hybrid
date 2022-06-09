import random
import math
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CcaHybrid:
    def __init__(self):
        self.BLOCK_SIZE_BYTES = 16

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        self.ciphertext, self.shared_key = self.encaps(
            self.private_key.public_key().public_numbers().n,
            self.private_key.public_key().public_numbers().e,
        )

        # New a cipher object
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.OFB(iv))
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        # Encrypt the actual bible
        self.bible_ciphertext = self.encrypt(encryptor)
        # Decaps and decrypt
        plaintext = self.decaps_decrypt(
            self.private_key.public_key().public_numbers().n,
            self.ciphertext,
            self.private_key.private_numbers().d,
            decryptor
        )
        # To see the decrypted bible, uncomment this line
        # print(plaintext)

    def encaps(self, n, e):
        while True:
            r = random.randint(1, n-1)
            if math.gcd(r, n) == 1:
                break
            else:
                print(f'r: {r} not valid since it is not co-prime to n: {n}')

        # Encrypt r using public key
        ciphertext = pow(r, e, n)

        # Hash r, H(r) = symmetric shared key
        digest = hashes.Hash(hashes.SHA256())

        # RSA key size is 2048 bits = 256 bytes
        digest.update(r.to_bytes(256, byteorder='big'))

        # H = Z_N -> {0, 1}^256 (256/8=32), use SHA-256 here
        # SHA512 outputs a 256-bit key
        shared_key = digest.finalize()
        return ciphertext, shared_key

    def encrypt(self, encryptor):
        ciphertext = []
        with open('./bible.txt', 'rb') as fd:
            line = fd.read(self.BLOCK_SIZE_BYTES)
            while line:
                ciphertext.append(encryptor.update(line))
                line = fd.read(self.BLOCK_SIZE_BYTES)

        ciphertext.append(encryptor.finalize())

        return ciphertext

    def decaps_decrypt(self, n, c, d, decryptor):
        # Compute r
        r = pow(c, d, n)

        # Get shared key, H(r) is the shared key
        # SHA-256 is deterministic, so we are guaranteed to get the same H(r) for the same given r
        digest = hashes.Hash(hashes.SHA256())
        digest.update(r.to_bytes(256, byteorder='big'))
        shared_key = digest.finalize()

        if shared_key != self.shared_key:
            print('The key client gets is not the same as the original one')
            return
        else:
            print(f'The client got {shared_key}, and it is the same as the original one')

        plaintext = []
        for c in self.bible_ciphertext:
            plaintext.append(decryptor.update(c))

        final = decryptor.finalize()
        if final:
            plaintext.append(final)
        return plaintext
