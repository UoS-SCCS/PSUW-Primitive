from collections import namedtuple
from fastecdsa.keys import export_key
from fastecdsa.encoding.pem import PEMEncoder
import importlib

ARKG = importlib.import_module('arkg.benchmarks.arkg')
DS = ARKG.ecdsa
DS_KGEN = ARKG.fastecdsa.keys.gen_keypair
ARKG_KGEN = ARKG.fastecdsa.keys.gen_keypair

Params = namedtuple('Params', 'curve')
Delegation = namedtuple('Delegation', 'warr ddata')
ProxySignature = namedtuple('ProxySignature', 'psig warr')

pp = Params(ARKG.P256)

def encode_key(key, as_bytes=False):
    if as_bytes:
        return export_key(key, pp.curve).encode()
    return export_key(key, pp.curve)
  
def decode_key(key, public=False, from_bytes=False):
    if from_bytes:
        key = key.decode()
    if public:
        return PEMEncoder.decode_public_key(key, pp.curve)
    return PEMEncoder.decode_private_key(key)[1]

def dkgen(pp):
    return DS_KGEN(pp.curve)

def pkgen(pp):
    return ARKG_KGEN(pp.curve)

def delegate(pp, skd, pkp):
    pkw, cred = ARKG.derive_pk(pkp, b'')
    sigma = list(DS.sign(encode_key(pkw), skd))
    sigma[1] = ARKG.P256.q-sigma[1] if sigma[1] >= (ARKG.P256.q-1)/2 else sigma[1]
    return Delegation([pkw, sigma], cred)

def psign(pp, skp, pkd, warr, ddata, m):
    pkw, sigma = warr
    cred = ddata
    assert DS.verify(sigma, encode_key(pkw), pkd)
    skw = ARKG.derive_sk(skp, cred)  # No need to assert, exception thrown if invalid.
    sig = list(DS.sign(m, skw))
    sig[1] = ARKG.P256.q-sig[1] if sig[1] >= (ARKG.P256.q-1)/2 else sig[1]
    return ProxySignature(sig, warr)

def pverify(pp, pkd, psig, m):
    sig, warr = psig
    pkw, sigma = warr
    assert sigma[1] < (ARKG.P256.q-1)/2
    assert sig[1] < (ARKG.P256.q-1)/2
    return DS.verify(sigma, encode_key(pkw), pkd) and DS.verify(sig, m, pkw)

if __name__ == '__main__':
    m = 'MESSAGE'

    skd, pkd = dkgen(pp)
    skp, pkp = pkgen(pp)
    warr, ddata = delegate(pp, skd, pkp)
    psig = psign(pp, skp, pkd, warr, ddata, m)

    if pverify(pp, pkd, psig, m):
        print('Proxy signature verification passed')
    else:
        print('Proxy signature verification failed')
