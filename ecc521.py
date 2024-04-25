from Crypto.Util import number

''' Elliptic Curve Cryptography '''
''' by Karl Zander '''

def gen_base_point(curve_point):
    base_point = number.getRandomRange(1, curve_point - 1)
    g = number.GCD(curve_point, base_point)
    while g != 1:
        base_point = number.getRandomRange(1, curve_point - 1)
        g = number.GCD(curve_point, base_point)
    return base_point

def gen_priv_key(base_point):
    priv_key = number.getRandomRange(1, base_point - 1)
    return priv_key

def gen_public_key(priv_key, base_point):
    pub_key = priv_key * base_point
    return pub_key

def gen_shared_key(priv_key, pub_key):
    return priv_key * pub_key

# P-521 Wierstrass curve W
curve_point = pow(2, 221) - 1

base_point = gen_base_point(curve_point)
privA_key = gen_priv_key(base_point)
pubA_key = gen_public_key(privA_key, base_point)

privB_key = gen_priv_key(base_point)
pubB_key = gen_public_key(privB_key, base_point)

shared_keyA= gen_shared_key(privA_key, pubB_key)
shared_keyB = gen_shared_key(privB_key, pubA_key)
print(shared_keyA, shared_keyB)
