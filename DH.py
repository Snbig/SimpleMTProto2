from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, ParameterFormat, Encoding, load_der_public_key, \
    load_der_parameters


class DH:
    def __init__(self):
        self.shared_key = None
        self.public_key = None
        self.private_key = None
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048,
                                                    backend=default_backend()).parameter_bytes(Encoding.DER,
                                                                                               ParameterFormat.PKCS3)

    def gen_private(self):
        self.private_key = load_der_parameters(self.dh_parameters, default_backend()).generate_private_key()
        return self.private_key

    def gen_public(self):
        self.public_key = self.private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return self.public_key

    def gen_shared_key(self, peer_public_key):
        self.shared_key = self.private_key.exchange(load_der_public_key(peer_public_key, default_backend()))
        return self.shared_key

