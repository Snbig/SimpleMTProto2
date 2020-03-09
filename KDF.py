import hashlib
from DH import DH


class KDF:
    def __init__(self, key, message_key, mode):
        self.mode = mode
        self.key = key
        self.aes_key = None
        self.aes_ie = None
        self.message_key = message_key
        self.payload_padded = None

    def KD(self):
        sha256_a = hashlib.sha256(self.message_key + self.key[self.mode:36 + self.mode]).digest()
        sha256_b = hashlib.sha256(self.key[40 + self.mode: 96 + self.mode] + self.message_key).digest()
        self.aes_key = sha256_a[0:8] + sha256_b[8:24] + sha256_a[24:32]
        self.aes_ie = sha256_b[0:8] + sha256_a[8:24] + sha256_b[24:32]
        return self.aes_key, self.aes_ie

