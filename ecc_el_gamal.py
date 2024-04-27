from Crypto.Util import number

''' Elliptic Curve El Gamal '''
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

def gen_public_key(priv_key, base_point, curve_point):
    pub_key = (priv_key * base_point) % curve_point
    return pub_key

def encrypt(msg, pub_key, base_point, curve_point):
    ephemeral_key = number.getRandomRange(1, curve_point - 1)
    c1 = (ephemeral_key * base_point) % curve_point
    c2 = (msg + (ephemeral_key * pub_key)) % curve_point
    return c1, c2

def decrypt(ctxt1, ctxt2, priv_key, curve_point):
    return ctxt2 - (ctxt1 * priv_key) % curve_point

msg = 123
# P-521 Wierstrass curve W
curve_point = pow(2, 221) - 1

base_point = gen_base_point(curve_point)
priv_keyA = gen_priv_key(base_point)
pub_keyA = gen_public_key(priv_keyA, base_point, curve_point)

ctxt1, ctxt2 = encrypt(msg, pub_keyA, base_point, curve_point)
ptxt = decrypt(ctxt1, ctxt2, priv_keyA, curve_point)
print(ctxt1, ctxt2)
print(ptxt)
