from Crypto.Util import number

''' P2 '''
''' by Karl Zander '''

def gen_key_field(psize):
    return number.getPrime(psize)

def gen_base_point(key_field):
    base_point = number.getRandomRange(1, key_field - 1)
    g = number.GCD(key_field, base_point)
    while g != 1:
        base_point = number.getRandomRange(1, key_field - 1)
        g = number.GCD(key_field, base_point)
    return base_point

def gen_pub_key(priv_key, base_point, key_field):
    pub_key = (priv_key * base_point) % key_field
    return pub_key

def gen_priv_key(base_point):
    priv_key = number.getRandomRange(1, base_point - 1)
    return priv_key

def gen_shared_key(pub_key, priv_key, key_field):
    return (pub_key * priv_key) % key_field


key_field = gen_key_field(521)
base_point = gen_base_point(key_field)

priv_keyA = gen_priv_key(base_point)
pub_keyA = gen_pub_key(priv_keyA, base_point, key_field)

priv_keyB = gen_priv_key(base_point)
pub_keyB = gen_pub_key(priv_keyB, base_point, key_field)

shared_keyA = gen_shared_key(pub_keyB, priv_keyA, key_field)
shared_keyB = gen_shared_key(pub_keyA, priv_keyB, key_field)
print(shared_keyA)
print(shared_keyB)
