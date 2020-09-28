import secrets
from Cryptodome.Cipher import AES
import os


class User(object):
    # Creates a new user with a key shared with the server along with a CBC initialization vector to be
    # used with the shared key
    def __init__(self, identity):
        self.identity = identity
        self.server_key = os.urandom(16)
        self.iv = os.urandom(8)

    def __repr__(self):
        return self.identity

# adapted from https://github.com/joestump/python-oauth2/blob/81326a07d1936838d844690b468660452aafdea9/oauth2/__init__.py#L165
def generate_nonce():
    return ''.join([str(secrets.randbelow(10)) for i in range(8)])

def needham_schroeder():
    A = User('A')
    encipher_as = AES.new(key=A.server_key, mode=AES.MODE_CTR, nonce=A.iv)
    decipher_as = AES.new(key=A.server_key, mode=AES.MODE_CTR, nonce=A.iv)
    B = User('B')
    encipher_bs = AES.new(key=B.server_key, mode=AES.MODE_CTR, nonce=B.iv)
    decipher_bs = AES.new(key=B.server_key, mode=AES.MODE_CTR, nonce=B.iv)

    print('A initiates contact with B.')
    initial_request = A.identity
    print('A to B: ' + A.identity)
    print()

    print('B acknowledges contact and sends {A, J}Kbs to A.')
    J = generate_nonce()
    request = ("{}, {}".format(initial_request, J)).encode('ASCII')
    to_a = encipher_bs.encrypt(request)
    print('B to A (encrypted using Kbs): ', to_a)
    print('B to A (values): ', "{}, J: {}".format(initial_request, J))
    print()

    print('A sends A, B, Na, {A, J}Kbs to S.')
    na = generate_nonce()
    to_s = ("{}, {}, {}, {}".format(A.identity, B.identity, na, to_a))
    print('A to S (encrypted using Kbs): ', to_s)
    print('A to S (values): ', "{}, {}, Na: {}, Encrypted: ({}, J: {})".format(A.identity, B.identity, na, A.identity, J))
    print()

    print('S sends {Na, B, Kab, {Kab, A, J}Kbs}Kas to A.')
    kab = os.urandom(16)
    to_b = decipher_bs.decrypt(to_a).decode('ASCII')
    to_b = to_b.split(',')
    # Makes sure the partner's name matches the caller
    if to_b[0] != A.identity:
        print('Wrong caller identity!')
        return
    to_b = ("{}, {}, {}".format(kab, A.identity, J)).encode('ASCII')
    to_b = encipher_bs.encrypt(to_b)
    request = "{}, {}, {}, {}".format(na, B.identity, kab, to_b).encode('ASCII')
    to_a = encipher_as.encrypt(request)
    print('S to A (encrypted using Kas on the outside and Kbs on the inside): ', to_a)
    print('S to A (values): ', "Na: {}, {}, Kab: {}, Encrypted: ({}, J: {})".format(na, B.identity, kab, A.identity, J))
    print()

    print('A checks Na and gets Kab. Forwards {Kab, A, J}Kbs to B.')
    final_info = decipher_as.decrypt(to_a).decode('ASCII')
    final_info = final_info.split(', ')
    print(final_info)
    # Checks to make sure the nonces match, ensuring a fresh key
    if final_info[0] != na:
        print('Key is not fresh!')
        return
    a_kab = final_info[2]
    print('A to B (encrypted using Kbs): ', to_b)
    print('A to B (values): ', "{}, J: {}".format(initial_request, J))
    print()

    print('B checks J and gets Kab. Sends {Nb}kab to A.')
    final_info = decipher_bs.decrypt(to_b).decode('ASCII')
    final_info = final_info.split(', ')
    print(final_info)
    # Checks to make sure the nonce is the same as the one provided at the beginning, ensuring a fresh key
    if final_info[-1] != J:
        print('Key is not fresh!')
        return
    b_kab = final_info[0]
    # Make sure kab is really equal
    #print(str(kab))
    #print(a_kab)
    #print(b_kab)
    assert(str(kab) == a_kab)
    assert (str(kab) == b_kab)
    assert (a_kab == b_kab)
    ab_iv = os.urandom(8)
    encipher_ab = AES.new(key=kab, mode=AES.MODE_CTR, nonce=ab_iv)
    decipher_ab = AES.new(key=kab, mode=AES.MODE_CTR, nonce=ab_iv)
    nb = generate_nonce()
    to_a = encipher_ab.encrypt(nb.encode('ASCII'))
    print('B to A (encrypted using Kab): ', to_a)
    print('B to A (values): Nb: ', nb)
    print()

    print('A verifies that B has received the message and sends their own verification.')
    verification = int(decipher_ab.decrypt(to_a).decode('ASCII'))
    request = str(verification - 1)
    to_b = encipher_ab.encrypt(request.encode('ASCII'))
    print('A to B (encrypted using Kab): ', to_b)
    print('A to B (values): Nb - 1: ', request)
    print()

    print('Protocol complete!')

if __name__ == '__main__':
    needham_schroeder()