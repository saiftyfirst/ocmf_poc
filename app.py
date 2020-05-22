import json
import os
from pathlib import Path

from modules.keymanager import KeyManager
from modules.utils import package_ocmf_message

algorithm = 'ecdsa'
algorithm_params = 'secp256k1'
hash_func = 'EMSA1(SHA-256)'

METER_SAMPLE_DIR = os.path.join(Path(__file__), 'meter_value_sample.json')


def main():
    key_manager = KeyManager(algorithm=algorithm, algorithm_params=algorithm_params, hash_func=hash_func)
    with open('meter_value_sample.json') as meter_val_json:
        msg = json.dumps(json.load(meter_val_json))
    signature = key_manager.sign(msg)

    algo_n_hash = algorithm.upper() + '-' + algorithm_params + '-' + hash_func[6:-1].replace('-', '')

    print('Use the following to test against the Transparency software: ')
    print('public_key: ', key_manager.get_public_key_as_hex())
    print('ocmf messgae: ', package_ocmf_message(msg, algo_n_hash, signature.hex()))


if __name__ == '__main__':
    main()
