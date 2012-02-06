import random
from hashlib import sha1
from Crypto.Util.number import long_to_bytes

def random_hex(length):
    # TODO - use secure random
    chars = map(str,range(10)) + list('abcdef')
    return ''.join([random.choice(chars) for _ in range(length)])


def create_public_key(modulus, generator, salt):
    exponent = int(random_hex(40), 16)
    public_key = pow(generator, exponent, modulus)
    return exponent, public_key

def verify_client_key(username, password, modulus, generator, salt, exponent, public_key, client_public_key):
    kay = 3
    u = int(sha1(long_to_bytes(public_key) + long_to_bytes(client_public_key)).hexdigest(), 16)

    if u % modulus == 0:
        raise Exception('invalid exponent...')

    userpassint = int(sha1( '%s:%s' % (username,password) ).hexdigest(),16)
    passint = int( sha1( long_to_bytes(salt) + long_to_bytes( userpassint ) ).hexdigest(), 16 )

    gtox = pow(generator, passint, modulus)

    neg_gtox_kay = (modulus - gtox) * kay

    key_base = (client_public_key + neg_gtox_kay) % modulus

    key_exponent = exponent + (u * passint)
    client_num = pow( key_base, key_exponent, modulus )
    client_hash = sha1( long_to_bytes(client_num) ).hexdigest()
    client_key = int(client_hash, 16)
    
    aeskey = hex(client_key)[2:-1] # remove 0x and L
    if len(aeskey) < 40:
        aeskey = '0' + aeskey
    if len(aeskey) > 40:
        aeskey = aeskey[:40]

    def compute_verify_client_key():
        xor_term = int(sha1(long_to_bytes(modulus)).hexdigest(),16) ^ int(sha1(long_to_bytes(generator)).hexdigest(),16)
        A = public_key
        B = client_public_key
        M1_pre_hash = ''.join( [ long_to_bytes(xor_term),
                                 long_to_bytes( int(sha1(username).hexdigest(),16) ),
                                 long_to_bytes( salt ),
                                 long_to_bytes( A ),
                                 long_to_bytes( B ),
                                 long_to_bytes( client_key ) ] )
        M1 = int(sha1(M1_pre_hash).hexdigest(),16)
        return M1

    M1 = compute_verify_client_key()
    return aeskey, client_key, M1

def verify(public_key, client_key, M1):
    A = public_key
    M2 = sha1( ''.join( [ long_to_bytes(A),
                          long_to_bytes(M1),
                          long_to_bytes(client_key) ] ) ).hexdigest()
    return int(M2, 16)
