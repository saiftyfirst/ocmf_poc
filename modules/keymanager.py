import os
from pathlib import Path

from botan import botan2 as bt

PRIVATE_KEY_DIR = os.path.join(Path(__file__).parent.parent, 'key/private-key.pem')
PUBLIC_KEY_PKCS8_DIR = os.path.join(Path(__file__).parent.parent, 'key/private-key-pkcs8.pem')
PUBLIC_KEY_DIR = os.path.join(Path(__file__).parent.parent, 'key/public-key.pem')


class KeyManager:

    def __init__(self, algorithm, algorithm_params, hash_func):
        self._rng = bt.RandomNumberGenerator()
        try:
            with open(PRIVATE_KEY_DIR, 'r') as private:
                data = private.read()
                self._key = bt.PrivateKey.load(data)
                assert (algorithm == self._key.algo_name())
        except (FileNotFoundError, AssertionError) as e:
            self._create(algorithm, algorithm_params)
        self._signing_obj = bt.PKSign(self._key, hash_func, der=True)
        self._verification_obj = bt.PKVerify(self._key.get_public_key(), hash_func, der=True)

    def _create(self, algorithm, algorithm_params):
        self._key = bt.PrivateKey.create(algorithm, algorithm_params, self._rng)
        with open(PRIVATE_KEY_DIR, 'w') as private, open(PUBLIC_KEY_DIR, 'w') as pub:
            private.write(self._key.to_pem())
            pub.write(self._key.get_public_key().to_pem())

    def sign(self, message):
        self._signing_obj.update(message)
        return self._signing_obj.finish(self._rng)

    def verify_signature(self, msg, signature):
        self._verification_obj.update(msg)
        return self._verification_obj.check_signature(signature)

    def get_public_key_as_hex(self):
        return self._key.get_public_key().to_der().hex()
