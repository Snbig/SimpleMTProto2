import tgcrypto
from KDF import KDF
import hashlib
import random


class Oracle:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.msg_key = None

    @staticmethod
    def pad(message):
        block_size = (len(message) + 16) - (len(message) % 16)
        random_pad_length = random.randint(12, 1024)
        while block_size - len(message) < random_pad_length:
            block_size = (block_size + 16) - (block_size % 16)
        pad = ((block_size - len(message)) * "\x14").encode()
        data = message + pad
        # padder = padding.PKCS7(block_size * 8).padder()
        # data = padder.update(message)
        # data += padder.finalize()
        return data

    def encrypt(self, message, mode):
        if mode == "org":
            mode = 0
        else:
            mode = 8
        message_len = f"{len(message):b}"
        length = f"{(32 - len(message_len)) * '0'}" + f"{message_len}"
        padded_message = Oracle.pad(length.encode() + message)
        msg_key_large = hashlib.sha256(self.secret_key[88 + mode:120] + padded_message).digest()
        self.msg_key = msg_key_large[8:24]
        kdf = KDF(self.secret_key, self.msg_key, "Enc")
        aes_key, aes_iv = kdf.KD()
        ige_encrypted = tgcrypto.ige256_encrypt(padded_message, aes_key, aes_iv)
        ige_encrypted_header_set = self.msg_key + ige_encrypted
        return ige_encrypted_header_set

    def decrypt(self, ciphertext, message_key, mode):
        if mode == "org":
            mode = 8
        else:
            mode = 0
        msg_key_from_cipher = message_key
        kdf = KDF(self.secret_key, msg_key_from_cipher, "Enc")
        aes_key, aes_iv = kdf.KD()
        ige_decrypted = tgcrypto.ige256_decrypt(ciphertext[16:], aes_key, aes_iv)
        msg_key_large = hashlib.sha256(self.secret_key[88 + mode:120] + ige_decrypted).digest()
        msg_key = msg_key_large[8:24]
        length = int(ige_decrypted[:32], 2)
        if msg_key == msg_key_from_cipher:
            plaintext = ige_decrypted[32:32 + length]
            return plaintext
        else:
            print("msg_key mismatch!!!")
