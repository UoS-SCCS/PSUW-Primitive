import importlib
from timeit import timeit
import os
import datetime
from collections import namedtuple
import fastecdsa
from cpuinfo import get_cpu_info
import psuw

ARKG = importlib.import_module('arkg.benchmarks.arkg')
Bench = namedtuple('Bench', 'raw avg max samples repeats alg param')


def bench(alg_func, param_func, samples=100, repeats=1):
    times = []
    for _ in range(samples):
        params = param_func()
        times.append(timeit(stmt=lambda: alg_func(*params), number=repeats))

    return Bench(times, sum(times)/len(times), max(times), samples, repeats, alg_func, param_func)


def res_line(title, res):
    if res is None:
        return f'{title}: N/A'

    return '{}: max={}, avg={}, alg={}, samples={}, iterations={}'.format(
        title, res.max, res.avg, res.alg.__name__, res.samples, res.repeats)


def format_output(scheme, delegate, sign, verify):
    print('\nBenchmarking results for scheme', scheme)
    print(res_line('DELEGATE', delegate))
    print(res_line('SIGN', sign))
    print(res_line('VERIFY', verify))


def message():
    return os.urandom(16)


def setup_psuw_delegate():
    skd, _ = psuw.dkgen(psuw.pp)
    _, pkp = psuw.pkgen(psuw.pp)
    return (None, skd, pkp)


def setup_psuw_sign():
    skd, pkd = psuw.dkgen(psuw.pp)
    skp, pkp = psuw.pkgen(psuw.pp)
    warr, ddata = psuw.delegate(None, skd, pkp)
    return (None, skp, pkd, warr, ddata, message())


def setup_psuw_verify():
    skd, pkd = psuw.dkgen(psuw.pp)
    skp, pkp = psuw.pkgen(psuw.pp)
    warr, ddata = psuw.delegate(None, skd, pkp)
    m = message()
    psig = psuw.psign(None, skp, pkd, warr, ddata, m)
    return (None, pkd, psig, m)


def setup_arkg_delegate():
    _, pk = ARKG.fastecdsa.keys.gen_keypair(ARKG.P256)
    return (pk, b'')


def setup_arkg_sign():
    sk, pk = ARKG.fastecdsa.keys.gen_keypair(ARKG.P256)
    _, cred = ARKG.derive_pk(pk, b'')
    return (message(), sk, cred)


def arkg_sign(m, sk, cred):
    skp = ARKG.derive_sk(sk, cred)
    ARKG.ecdsa.sign(m, skp)


def setup_arkg_verify():
    sk, pk = ARKG.fastecdsa.keys.gen_keypair(ARKG.P256)
    pkp, cred = ARKG.derive_pk(pk, b'')
    skp = ARKG.derive_sk(sk, cred)
    m = message()
    sig = ARKG.ecdsa.sign(m, skp)
    return (sig, m, pkp)


def setup_ecdsa_sign():
    sk, pk = fastecdsa.keys.gen_keypair(fastecdsa.curve.P256)
    return (message(), sk)


def setup_ecdsa_verify():
    sk, pk = fastecdsa.keys.gen_keypair(fastecdsa.curve.P256)
    m = message()
    sig = fastecdsa.ecdsa.sign(m, sk)
    return (sig, m, pk)


if __name__ == '__main__':
    print(f'Benchmarking on {get_cpu_info()["brand_raw"]} at {datetime.datetime.now()}')

    format_output(
        'PSUW',
        bench(psuw.delegate, setup_psuw_delegate),
        bench(psuw.psign, setup_psuw_sign),
        bench(psuw.pverify, setup_psuw_verify),
    )

    format_output(
        'ARKG',
        bench(ARKG.derive_pk, setup_arkg_delegate),
        bench(arkg_sign, setup_arkg_sign),
        bench(ARKG.ecdsa.verify, setup_arkg_verify),
    )

    format_output(
        'ECDSA',
        None,
        bench(fastecdsa.ecdsa.sign, setup_ecdsa_sign),
        bench(fastecdsa.ecdsa.verify, setup_ecdsa_verify),
    )
