from Crypto.Util import number

''' Elliptic Curve Cryptography '''
''' by Karl Zander '''

def gen_base_point(psize):
    curve_point = number.getPrime(psize)
    base_point = number.getRandomRange(1, curve_point - 1)
    g = number.GCD(curve_point, base_point)
    while g != 1:
        base_point = number.getRandomRange(1, curve_point - 1)
        g = number.GCD(curve_point, base_point)
    return curve_point, base_point

def gen_priv_key(base_point):
    priv_key = number.getRandomRange(1, base_point - 1)
    return priv_key

def gen_public_key(priv_key, base_point):
    pub_key = priv_key * base_point
    return pub_key

def gen_shared_key(priv_key, pub_key):
    return priv_key * pub_key

# Random Curve Example
curve_point, base_point = gen_base_point(256)
privA_key = gen_priv_key(base_point)
pubA_key = gen_public_key(privA_key, base_point)

privB_key = gen_priv_key(base_point)
pubB_key = gen_public_key(privB_key, base_point)

shared_keyA= gen_shared_key(privA_key, pubB_key)
shared_keyB = gen_shared_key(privB_key, pubA_key)
print(shared_keyA, shared_keyB)

