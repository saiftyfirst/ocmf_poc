base_string = 'OCMF|<meter_value>|{"SA":"<algo_n_hash>","SD":"<signature>","SE":"base64"}'


def package_ocmf_message(msg, algo_n_hash, signature):
    return base_string\
        .replace('<meter_value>', msg)\
        .replace('<algo_n_hash>', algo_n_hash)\
        .replace('<signature>', signature)
